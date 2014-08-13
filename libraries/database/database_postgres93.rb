#
# RightScale Tools
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

require 'fileutils'

module RightScale
  module Tools
    class DatabasePostgres < RightScale::Tools::HBDatabase

      include FileUtils::Verbose

      def initialize(user, passwd, data_dir, timeout, max_attempts, logger=Logger(stdout))
        require 'rubygems'
        Gem.clear_paths
        require 'pg' 
        require 'rightscale_tools'                   
        require 'rightscale_tools/premium/db/common/d_b_utils'
        # require 'rightscale_tools/premium/db/common/d_b_utils_postgres91'
        require File.dirname(__FILE__) +  '/d_b_utils_postgres93.rb'

        super("PostgreSQL", user, passwd, data_dir, timeout, max_attempts, logger)
        @db = create_shared_premium_util
      end

      def start
        @log.info "Starting database..."
        @log.info "Ensuring db is started..."
        @db.ensure_db_started
        @log.info "Ensuring db is ready..."
        @db.ensure_db_ready
      end

      def move_datadir(datadir_dst, datadir_src)
        unless ::File.symlink?(datadir_src)
          files = Dir.glob(datadir_src+"/*")
          FileUtils.cp_r files, datadir_dst+"/."
          FileUtils.chown_R("postgres", "postgres", "#{datadir_dst}")
          FileUtils.rm_rf(datadir_src)
          File.symlink(datadir_dst, datadir_src)
          File.chmod 0700, "#{datadir_dst}"
        end
      end

      def reset(datadir_dst, datadir_src)
        stop
        # Verifies 'postmaster' processes running as 'postgres' do not exist.
        begin
          Timeout.timeout(10) do
            begin
              # If no processes are found, a non-zero exit code is sent,
              # which is what we are looking for.
              `pgrep -U postgres postmaster`
              exit_code = $?
            end until exit_code != 0
          end
        rescue Timeout::Error
          raise "FATAL: postgres still running"
        end

        FileUtils.rm_rf(LOCK_PID_FILE)
        FileUtils.rm_rf(backup_touch_filename)

        current_pid = $$

        # Preserve all *.conf files
        FileUtils.mkdir_p("/var/tmp/#{current_pid}")
        conf_files = Dir.glob(datadir_src + "/*[^recovery].conf")
        FileUtils.cp_r(conf_files, "/var/tmp/#{current_pid}", :preserve => true)

        FileUtils.rm_rf(datadir_dst)
        FileUtils.rm_rf(datadir_src)

        # initdb recreates datadir_src directory
        @log.info `service postgresql-9.3 initdb`
        begin
          Timeout.timeout(10) do
            until ::File.directory?(datadir_src); end
          end
        rescue Timeout::Error
          raise "FATAL: postgres initdb failed"
        end

        FileUtils.cp_r(
          "/var/tmp/#{current_pid}/.",
          "#{datadir_src}/",
          :preserve => true
        )

        FileUtils.chown("postgres", "postgres", datadir_src)
        File.chmod(0700, datadir_src)

        FileUtils.rm_rf("/var/tmp/#{current_pid}")
      end

      def restore_snapshot(datadir_dst = "/mnt/storage", datadir_src = "/var/lib/pgsql/9.3/data", recovery_config_file = Dir.glob(datadir_dst+"/recovery.*"))
        stop

        # Verifies no tasks named 'postmaster' running as 'postgres' exists.
        begin
          Timeout.timeout(10) do
            begin
              # If no processes are found, a non-zero exit code is sent.
              `pgrep -U postgres postmaster`
              exit_code = $?
            end until exit_code != 0
          end
        rescue Timeout::Error
          raise "FATAL: postgres still running"
        end

        FileUtils.rm_rf(LOCK_PID_FILE)
        FileUtils.rm_rf(backup_touch_filename)
        FileUtils.rm_rf(recovery_config_file)
        FileUtils.chown_R("postgres", "postgres", datadir_dst)

        # Removing installed datadir to allow symlink of mounted volume.
        FileUtils.rm_rf(datadir_src)
        File.symlink(datadir_dst, datadir_src)

        File.chmod(0700, datadir_dst)
      end

      def set_privileges(preset = "administrator", username = nil, password = nil, db_name = "*.*")

        # Open database connection and santize our inputs
        conn = @db.get_connection
        username = conn.escape_string(username)
        password = conn.escape_string(password)
        db_name = conn.escape_string(db_name)
        admin_role = "#{preset}"
        user_role = "users"

        # Extracted from pg_postgres/definitions/db_postgres_set_privileges #Ravi
        case priv_preset
        when 'administrator'
        # Create group roles, don't error out if already created.  Users don't inherit "special" attribs
        # from group role, see: http://www.postgresql.org/docs/9.3/static/role-membership.html
          conn.exec("CREATE ROLE #{admin_role} SUPERUSER CREATEDB CREATEROLE INHERIT LOGIN")

        # Enable admin/replication user
          conn.exec("CREATE USER #{username} ENCRYPTED PASSWORD '#{password}'")

        # Grant role previleges to admin/replication user
          conn.exec("GRANT #{admin_role} TO #{username}")

        when 'user'
        # Create group roles, don't error out if already created.  Users don't inherit "special" attribs
        # from group role, see: http://www.postgresql.org/docs/9.3/static/role-membership.html
          conn.exec("CREATE ROLE #{user_role} NOSUPERUSER CREATEDB NOCREATEROLE INHERIT LOGIN")

        # Set default privileges for any future tables, sequences, or functions created.
          conn.exec("ALTER DEFAULT PRIVILEGES FOR ROLE #{user_role} GRANT ALL ON TABLES to #{user_role}")
          conn.exec("ALTER DEFAULT PRIVILEGES FOR ROLE #{user_role} GRANT ALL ON SEQUENCES to #{user_role}")
          conn.exec("ALTER DEFAULT PRIVILEGES FOR ROLE #{user_role} GRANT ALL ON FUNCTIONS to #{user_role}")

        # Enable application user
          conn.exec("CREATE USER #{username} ENCRYPTED PASSWORD '#{password}'")
          conn.exec("GRANT #{user_role} TO #{username}")
        else
          raise "only 'administrator' and 'user' type presets are supported!"
        end

        conn.finish
      end

      # Get DB handle object
      # Extracted from db_postgres/libraries/helper.rb
      # Orig used Chef::Log and had node as arg
      #
      # === Parameters
      # host(String):: Hostname of server holding database
      #
      # === Return
      # conn(Postgres):: Postgres handle
      def get_connection(host = @host, user= @user)
        info_msg = "PostgreSQL connection to #{host}"
        info_msg << ": opening NEW PostgeSQL connection."
        conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)
        @log.info(info_msg)
        # this raises if the connection has gone away
        conn.ping
        return conn
      end

      # Send DB query and return results
      #
      # === Parameters
      # query(String):: Query string to send to DB
      # hostname(String):: Hostname of server holding database
      # timeout(Int):: Timeout in seconds for query request
      # attempts(Int):: Number of attempts after timeout
      #
      # === Return
      # result(Hash):: DB output to query
      def do_query(query, hostname = 'localhost', timeout = nil, attempts = 1)
        count = 0
        while(count < attempts) do
          begin
           info_msg = "Doing SQL Query: HOST=#{hostname}, QUERY=#{query}"
           info_msg << ", TIMEOUT=#{timeout}" if timeout
           info_msg << ", NUM_TRIES=#{attempts}" if attempts > 1
           @log.info(info_msg)
           result = nil
           if timeout
             SystemTimer.timeout_after(timeout) do
               conn = get_connection(hostname, username)
               result = conn.exec(query)
             end
           else
             conn = get_connection(hostname, username)
             result = conn.exec(query)
           end
          return result.get_result if result
          return result
          rescue Exception => e
            is_timeout = (e == Timeout::Error)
            @log.info("Timeout occurred during postgres query:#{e}") if is_timeout
            @log.info("Unexpected exception: #{e.message}") unless is_timeout
            count += 1
            if (count >= attempts)
              raise "FATAL: retry count reached"
            else
              @log.info("Retrying attempt #{count} of #{attempts}")
            end
          end
        end
      end

      def write_backup_info_file(master_uuid, master_ip, is_master, provider, version)
        masterstatus = Hash.new
        masterstatus['Master_IP'] = master_ip
        masterstatus['Master_instance_uuid'] = master_uuid
        if is_master
          log_info "Backing up Master info"
        else
          log_info "Backing up slave replication status"
          masterstatus['File_position'] = execute("/usr/pgsql-9.3/bin/pg_controldata /var/lib/pgsql/9.3/data | grep 'Latest checkpoint location:' | awk '{print $NF}'", :return_output => true)
        end
        log_info "Saving master info...:\n#{masterstatus.to_yaml}"
        ::File.open(::File.join(@data_dir, 'rs_snapshot_position.yaml'), ::File::CREAT|::File::TRUNC|::File::RDWR) do |out|
          YAML.dump(masterstatus, out)
        end
      end


      # == Internal Methods
      #
      # The following methods are internal utils used by the above "step" methods and are not
      # intended to be used outside this class.
      #
      protected

      # Required is_pristine code
      def is_pristine?
        @db.is_db_pristine?(nil)
      end

      private

      # Instantiates our premium DB tools class
      #
      # This is out premium DBtools class that is shared with our RightScript
      # based 11H1 ServerTemplates.
      #
      # See the premium/README.rdoc for more information.
      #
      def create_shared_premium_util
        RightScale::DBUtilsPostgreSQL.new
      end

    end
  end
end
