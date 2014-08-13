#
# RightScale Tools
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

require 'fileutils'
require 'rightscale_tools'

module RightScale
  module Tools
    class HBDatabase
      include RightScale::Tools::Common

      # Defaults
      MAX_SNAPSHOTS = 10
      KEEP_DAILIES = 14
      KEEP_WEEKLIES = 10
      KEEP_MONTHLIES = 12
      KEEP_YEARLIES = 1
      LOCK_PID_FILE = '/var/run/rightscale_tools_database_lock.pid'

      # Create specified database
      #
      # === Parameters
      # type(Symbol):: Specifies which type of database object to create
      #
      # === Return
      # RightScale::Tools::Database object
      def self.factory(
        type,
        user,
        passwd,
        data_dir=nil,
        logger=Logger(stdout),
        timeout=600,
        max_attempts=3
      )
        case type
        when :mysql
          require 'rightscale_tools/database/database_mysql'
          RightScale::Tools::DatabaseMysql.new(user, passwd, data_dir, timeout, max_attempts, logger)
        when :mysql55
          require 'rightscale_tools/database/database_mysql55'
          RightScale::Tools::DatabaseMysql55.new(user, passwd, data_dir, timeout, max_attempts, logger)
        when :postgres
          # require 'rightscale_tools/database/database_postgres'
          # require 'database/database_postgres93'
          require File.dirname(__FILE__) +  '/database/database_postgres93.rb'          
          RightScale::Tools::DatabasePostgres.new(user, passwd, data_dir, timeout, max_attempts,logger)
        else
          raise "ERROR: Database type #{type} is not currently supported"
        end
      end

      # == Database steps
      #
      # The following methods are generic database "steps" that are used by the action_* methods above
      # These are currently a thin wrapper of logic over our legacy premium d_b_utils, but will fill
      # out once the legacy SVN repo is decommisioned.
      #
      # In the meintime, perhaps a git submodule would be better
      #

      def stop
        @log.info "Stopping database..."
        @db.db_service_stop
      end

      def start
        @log.info "Starting database..."
        @db.db_service_start
      end

      def status
        @db.execute_db_service_command( nil , "status" )
      end

      def lock
        @log.info "Timeout value for acquiring lock set to #{@timeout} seconds..."
        db_lock = @db.flush_and_lock_db( @host, @user, @password, @timeout,  @max_attempts)
        raise "Unable to Aquire Lock" if db_lock == nil
        File.open(LOCK_PID_FILE, 'w') do |io|
          io.write("#{db_lock}\n")
        end
      end

      def unlock
        db_lock = IO.read(LOCK_PID_FILE).chomp.to_i
        @db.release_lock_from_helper(db_lock)
        FileUtils.rm_rf(LOCK_PID_FILE)
      end

      def is_pristine?
        raise "You must override is_pristine? in #{self.to_s}"
      end

      def reset(datadir, datadir_relocate)
        raise "You must override reset in #{self.to_s}"
      end

      def do_query(query = @query, hostname = @host, timeout = nil, tries = 1)
        raise "You must override do_query in #{self.to_s}"
      end

      # Get database connection
      #
      # === Parameters
      # host(String):: hostname or ip of database
      #
      # === Return
      # (Connection):: connection to database
      def get_connection(host = @host)
        raise "You must override get_connection in #{self.to_s}"
      end

      # == Restore steps
      #
      def pre_restore_sanity_check(force = false)
        begin
          @db.sanity_checks(@host)
          @log.warn "Forcing restore even if database is not empty" if force

          # Abort if the DB has already some databases (other than the standard setup)..
          # unless we have the force flag
          unless is_pristine?
            @log.warn "Some contents already exists in the DB."
            raise "Database is not empty (and force option not specified)." unless force
          end
        rescue Exception => e
          raise "ERROR: failed pre-restore checks! Msg: #{e.message}\n#{e.backtrace}"
        end
      end

      def post_restore_sanity_check(ignore_version = false)
        @log.info "Checking for master info file..."
        master_info= YAML::load_file("#{@pos_file}")
        raise "Position and file not saved!" unless master_info['File'] && master_info['Position']
        unless ignore_version
          @log.info "Checking database version used to take snapshot..."
          snap_db_version = master_info['DB_version']
          db_version = get_version()
          raise "Snapshots from #{@dbtype} version #{snap_db_version}, not compatible with current version #{db_version}." unless @db.compatible_versions?(db_version, snap_db_version)
        end
      end

      def post_restore_cleanup
        # 6- Potentially delete the replication info file (in case the restore is from a slave backup)
        # TODO - This can be from a slave - must delete the replication/bin-log/relay log files
        @log.info "Deleting master.info (if exists)"
        `rm -f #{@data_dir}/master.info`
        @log.info "Deleting relay logs (if they exist)"
        `rm -f #{@data_dir}/*-relay-log.index #{@data_dir}/*.err #{@data_dir}/mysql-relay-bin.* #{@data_dir}/relay-log.info`
        @log.info "Deleting any restored pid files if they exist"
        `rm -f #{@data_dir}/*.pid`

        @log.info "Updating data directory permissions..."
        @db.update_permissions(@data_dir)
        # Touch a file to let us monitor when the backup completed
        time = Time.new
        @log.info "Recreated backup file at #{backup_touch_filename} with timestamp '#{time}'."
        ::File.open(backup_touch_filename, "w") { |f| f.write(time) }
      end


      # == Backup steps
      #

      def pre_backup_check
        @log .info "Creating mutually exclusive backup lock"
        @db.sanity_checks(@host)
        raise "ERROR: you must setup a block_device before a backup." unless File.directory?(@data_dir)
        # db_config = get_db_file_config
        # Check if there's something in the DB to back up
        # Exit if the DB has no databases (other than the standard setup)
        # Always do a snapshot - even if the DB is pristine
        #  if( is_pristine?( nil , db_config ) ) then
        #    @log.error "Database is empty, nothing to backup!"
        #    exit(-1)
        #  end
      end

      def write_backup_info
        @db.write_backup_info_file(backup_info_filename)
      end

      def validate_backup
        # TODO?
        # master_info = load_replication_info
        # raise "Position and file not saved!" unless master_info['Master_instance_uuid']
        # # Check that the snapshot is from the current master or a slave associated with the current master
        # if master_info['Master_instance_uuid'] != node[:db][:current_master]
        #   raise "FATAL: snapshot was taken from a different master! snap_master was:#{master_info['Master_instance_uuid']} != current master: #{node[:db][:current_master]}"
        # end
      end

      def post_backup_steps
        # Touch a file to let us monitor when the backup completed
        time = Time.new
        @log.info "Recreated backup file at #{backup_touch_filename} with timestamp '#{time}'."
        ::File.open(backup_touch_filename, "w") { |f| f.write(time) }
        # Delete backup info file
        ::File.delete(backup_info_filename) if ::File.exists?(backup_info_filename)
      end

      # == Relication and Failover (HA) Steps
      #

      # Set the replication privileges so the new slaves can replicate from it
      # (possibly overwritting privileges that were restored)
      def set_replication_grants
        @log.info "Granting rep rights..."
        con = @db.get_connection
        @db.set_replication_grants(con)
        @log.info "rights set."
        con.close
      end

      def grant_replication_slave
        #TODO
      end

      def wipe_existing_runtime_config
        @db.wipe_existing_runtime_config_files(@host, @data_dir)
      end

      def reconfigure_replication(hostname = @host, newmaster_host=nil, newmaster_logfile=nil, newmaster_position=nil)
       #TODO
       #@db.reconfigure_replication_info( con , newmaster_host, rep_user, rep_pass, newmaster_file, newmaster_position)
      end

      def promote
        #TODO
      end


      # == Misc steps
      #

      def get_file_config
        con = @db.get_connection
        cfg=@db.get_db_file_config_from(con)
        con.close
        cfg
      end

      def move_datadir(datadir_dst, datadir_src)
        raise "You must override move_datadir in #{self.to_s}"
      end

      def symlink_datadir(datadir, datadir_relocate)
        unless ::File.symlink?(datadir)
          FileUtils.rm_rf(datadir)
          File.symlink(datadir_relocate, datadir)
        end
      end

      def set_privileges(preset, username, password, db_name)
        raise "You must override set_privileges in #{self.to_s}"
      end


      # Get master database info by parsing tags hash
      #
      # === Parameters
      # tag_hash(Hash):: hash of tags from server_collection resource or rs_tag --query
      # current_uuid(String):: RightScale UUID of the current VM
      # from_cli(Boolean):: is tag hash from rs_tag command-line call?
      # === Return
      # (Boolean, String, String):: is_master, master_uuid, master_ip
      def master_info_from_tags(tag_hash = {}, current_uuid = "", from_cli = false)
        collect = {}
        is_master, uuid, ip = false, nil, nil

        tag_hash.each do |id, tags|
          tags = tags["tags"] if from_cli # needed for cli rs_tag output
          active = tags.select { |s| s =~ /rs_dbrepl:master_active/ }
          my_uuid = tags.detect { |u| u =~ /rs_dbrepl:master_instance_uuid/ }
          my_ip_0 = tags.detect { |i| i =~ /server:private_ip_0/ }
          most_recent = active.sort.last
          collect[most_recent] = my_uuid, my_ip_0 unless most_recent == nil
        end

        @log.debug "collect: #{collect.inspect}"
        most_recent_timestamp = collect.keys.sort.last
        current_master_uuid, current_master_ip = collect[most_recent_timestamp]
        if current_master_uuid =~ /#{current_uuid}/
          @log.info "THIS instance is the current master"
          is_master = true
        end
        if current_master_uuid
          uuid = current_master_uuid.split(/=/, 2).last.chomp
        else
          @log.info "No current master db found"
        end
        if current_master_ip
          ip = current_master_ip.split(/=/, 2).last.chomp
        else
          @log.info "No current master ip found"
        end
        @log.info "Found current master: #{uuid} ip: #{ip} active at #{most_recent_timestamp}" if uuid && ip

        # return master info
        return [is_master, uuid, ip]
      end


      # == Internal Methods
      #
      # The following methods are internal utils used by the above "step" methods and are not
      # intended to be used outside this class.
      #
      protected

      def backup_info_filename
        "#{@pos_file}"
      end

      def backup_touch_filename
        "/var/run/db-backup"
      end

      def initialize(
        type,
        user,
        passwd,
        data_dir=nil,
        timeout=600,
        max_attempts=3,
        logger=Logger(stdout)
      )

        @host = nil
        @user = user
        @password = passwd
        @data_dir = data_dir
        @data_dir ||= RightScale::DBUtils"#{type}"::DBMountPoint
        @pos_file = "#{@data_dir}/rs_snapshot_position.yaml"
        @dbtype = type
        @timeout = timeout
        @max_attempts = max_attempts
        @log = logger
      end


    end
  end
end
