#
# RightScale Tools
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

require 'rubygems'
require 'pg'
require 'fileutils'
require 'system_timer'

# require File.dirname(__FILE__) +  '/../common/d_b_utils.rb'
require 'rightscale_tools/premium/db/common/d_b_utils'

module RightScale
  class DBUtilsPostgreSQL
    include RightScale::DBUtils

    DBMountPoint = "/mnt/storage"
    SAVED_MASTER_POS_FILE="rs_snapshot_position.yaml"
    MASTER_FILE=SAVED_MASTER_POS_FILE
    LOCK_PID_FILE = '/var/run/rightscale_tools_database_lock.pid'    
    attr_reader :rep_user, :rep_pass, :conf_filename, :data_directory
    
    def initialize(params = {})
      ### Variables
      # PostgreSQL user and password to use at the slave DB to perform replication
      # This needs to match the deltaset that configure the master DB...
      # This user needs superuser access
      @rep_user=params[:rep_user].to_s.downcase
      @rep_pass=params[:rep_pass]

      # if running outside runrightscripts.rb, this variable is unset.
      ENV['RS_DISTRO'] = `lsb_release -is`.chomp.downcase unless ENV['RS_DISTRO']
      # Default position of the postgresql.conf configuration file
      case ENV['RS_DISTRO'].to_s
        when "ubuntu"
          @conf_filename = "/etc/postgresql/9.3/main/postgresql.conf"
          @data_directory = "/var/lib/postgresql/9.3/main"
          @service_name = "postgresql"
        when "centos", "redhatenterpriseserver"
          @conf_filename = "/var/lib/pgsql/9.3/data/postgresql.conf"
          @data_directory = "/var/lib/pgsql/9.3/data"
          @service_name = "postgresql-9.3"
        else
          raise "FATAL: Unsupported Distro: #{ENV['RS_DISTRO']}"
      end    
    end

  
    ### RS Tools 2.0 interface methods

    # Get database connection
    #
    # === Parameters
    # host(String):: hostname or ip of database
    # user(String):: user to connect as
    #
    # === Return
    # (Connection):: connection to database
    def get_connection()
      #PGconn.new("host", nil, nil, nil, nil, "user", nil)
      conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)
    end

    # Query database for version string
    # 
    # === Return
    # (String):: database version
    # Need to parse the valid version string from query result
    def get_version
      conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)
      rs = conn.exec('select version()').get_result
      db_version = rs["version()"]
      puts "Detected PostgreSQL version at #{db_version}."
      db_version
    end

    # Update permission so all files are owned by database service
    #
    # === Parameters
    # data_dir(String):: path to PostgreSQl data dir
    def update_permissions(data_dir)
      FileUtils.chown_R 'postgres', 'postgres', data_dir
    end

    ### Miscelaneous  ###
    
    def write_backup_info_file(filepath)
      slavestatus = nil
      # if slavestatus is nil this would indicate we are on a master instance
      # This tool is designed to be called with optional options[:from_master].  If we receive this option then we can safely use the check below since we know the caller (in this case the cron template script) has done a DNS check and set options[:from_master]
      if slavestatus == nil && options[:from_master] == "true"
        conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)
        masterstatus = conn.exec('select version()').get_result
        puts "Detected this is a Master instance"
        masterstatus['Master_IP'] = db.get_ip_from_ifconfig(nil)
        masterstatus['Master_instance_id'] = ENV['EC2_INSTANCE_ID']
      else
        puts "Detected this is a Slave instance"
        masterstatus = Hash.new
        # Need to get the master hostname from slave status and then resolve to get the IP
        masterhost = slavestatus['Master_Host']
        if masterhost =~ /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/
          # masterhost is an IP already
          masterip = masterhost
        else
          # masterhost is a hostname
          masterip = masterstatus['Master_IP'] = `host -4 -t A #{masterhost}`.split(/ /)[3].chomp
        end
        masterstatus['Master_IP'] = masterip
        masterstatus['Master_instance_id'] = `ssh #{masterhost} 'source /var/spool/cloud/meta-data.sh  2>&1 > /dev/null&& echo $EC2_INSTANCE_ID'`.chomp
      end

      # Add db version to masterstatus
      r = conn.exec('select version()').get_result
      masterstatus['DB_version'] = r["version()"]

      puts "Saving master info...:\n#{masterstatus.to_yaml}"
      File.open(filepath, File::CREAT|File::TRUNC|File::RDWR) do |out|
       YAML.dump(masterstatus, out)
      end
    end    

    # Util function that returns true if Major (x.x) version numbers are the same
    # Intended for the results of "select version from pg_catalog.version();" to be passed as version params.
    def compatible_versions?(db_version, db_arch, snapshot_version, snapshot_arch)
      raise "ERROR: unexpected version format for db_version param (#{db_version})" unless db_version =~ /(\d+\.)(\d+)(\.\d+)*/
      raise "ERROR: unexpected version format for snapshot_version param (#{snapshot_version})" unless snapshot_version =~ /(\d+\.)(\d+)(\.\d+)*/
      # compare version array containing only Major number
      ( (db_version.split('.').slice(0,2) == snapshot_version.split('.').slice(0,2)) && (db_arch == snapshot_arch) ) 
    end

    def db_info(host=nil)
      _host = (host!=nil) ? "-h #{host}" : ""

      res = `env PGCONNECT_TIMEOUT=30 psql -U postgres -qt -c "select version from pg_catalog.version()"`
      raise RemoteExecException.new(host,$?,res) if $? != 0
      res_split = res.split(' ')

      _db_info = Hash.new
      _db_info['version'] = res_split[1]
      _db_info['arch'] = res_split[res_split.length-1]

      return _db_info
    end

    def detect_if_master?(host=nil)
      res = `env PGCONNECT_TIMEOUT=30 psql -U postgres -qt -c "show transaction_read_only"`.strip
      raise RemoteExecException.new($?,res) if $? != 0
      return true if res =~ /off/
    end
    
    # Attempts to start the DB several times (sleeping in between)
    def ensure_db_started(host=nil)      
      success = false
      5.times {|attempt|
        success = ensure_db_started_internal(host)
        break if success 
        puts "Error starting DB: attempt #{attempt}. Trying again..."
        attempt +=1
        sleep 2
      }
      
      if( success == true )
        puts "Database started OK."
      else
        puts "Error starting DB. Giving up..."
        raise RemoteExecException.new(nil,$?,"Error starting DB") 
      end  
      success      
    end

    def ensure_db_ready
      # 1- Check if the host has PostgreSQL running 
      raise "DB was not up and couldn't be started. Aborting..." if  ensure_db_started == false
      30.times {|attempt|
        res = `env PGCONNECT_TIMEOUT=30 psql -U postgres -q -c "SELECT NOW()"`
        break if $? == 0
        puts "Error: DB not ready yet. Attempt #{attempt}. Trying again..."
        attempt +=1
        sleep 10
      }

      if( $? == 0 )
        puts "Database is ready."
      else
        puts "Error: DB has still not completed recovery. Giving up..."
        raise RemoteExecException.new(nil,$?,"Timeout while waiting for recovery.")
      end
      $? == 0
    end
    
    # It executes a service postgresql stop on the specified node
    # It returns the output of the status command on success or an exception if failure
    def db_service_stop( host=nil )
      return execute_db_service_command( host , "stop" )
    end

    # It executes a service postgresql start on the specified node (if it's not running already)
    # It returns the output of the status command on success or an exception if failure
    def db_service_start( host=nil )
      return execute_db_service_command( host , "start" )      
    end

    # It executes a service postgresql 'command' on the specified node
    # It returns the output of the status command after performing the action (or a RemoteExecException if an error or inconsistency is detected
    def execute_db_service_command( host , action )
      if host != nil
        if `ssh #{host} lsb_release -i`.downcase =~ /ubuntu/
          host_os = "ubuntu"
        else
          host_os = "centos"
        end
      else
        host_os = ENV['RS_DISTRO']
      end

      if host_os == 'ubuntu'
        pgsql_service = "postgresql"
        pgsql_started_tag = "Running clusters: \d+"
        pgsql_stopped_tag = "Running clusters:$"
      else
        pgsql_service = "postgresql-9.3"
        pgsql_started_tag = "is running"
        pgsql_stopped_tag = "is stopped"
      end

      exec_prefix = (host!=nil) ? "ssh  -o StrictHostKeyChecking=no #{host} ":"" 
        action_res = `#{exec_prefix} service #{pgsql_service} #{action}`
      action_errno = $?
      status_res = `#{exec_prefix} service #{pgsql_service} status`
  
      if( action == "stop" )
        #If we stopped the DB but the status says it is running, throw an exception with the output of the initial action
        raise RemoteExecException.new(host,action_errno,"Error stopping DB:\n"+action_res) if status_res =~ /#{pgsql_started_tag}/ 
      elsif (action == "start")
        #If we started the DB but the status says it is stopped, throw an exception with the output of the initial action
        raise RemoteExecException.new(
          host,
          action_errno,
          "Error starting DB:\n#{action_res}"
        ) if status_res =~ /#{pgsql_stopped_tag}/
      end
      #if the action succesded (or it is another not stop/start action), just return the result of the status
      return status_res
    end

    # Reconfigure the replication parameters.
    def reconfigure_replication_info(newmaster_host)
      File.open("/var/lib/pgsql/9.3/data/recovery.conf", File::CREAT|File::TRUNC|File::RDWR) do |f|
        f.puts("standby_mode='on'\nprimary_conninfo='host=#{newmaster_host} user=#{@rep_user} password=#{@rep_pass}'\ntrigger_file='/var/lib/pgsql/9.3/data/recovery.trigger'")
      end
      return $? == 0
    end 

    def rsync_db(newmaster_host)
      puts `su - postgres -c "env PGCONNECT_TIMEOUT=30 /usr/pgsql-9.3/bin/pg_basebackup -D /var/lib/pgsql/9.3/backups -U #{rep_user} -h #{newmaster_host}"`
      puts `su - postgres -c "rsync -av /var/lib/pgsql/9.3/backups/ /var/lib/pgsql/9.3/data --exclude postgresql.conf --exclude pg_hba.conf"`
      return $? == 0
    end

    def write_trigger()
      File.open("/var/lib/pgsql/9.3/data/recovery.trigger", File::CREAT|File::TRUNC|File::RDWR) do |f|
        f.puts(" ")
      end
    end
 
   def sanity_checks(host=nil)
      # Perform an initial connection forcing to accept the keys...to avoid interaction.
      accept_ssh_key(host) if host 

      # Check if the host has postgresql running (abort if not)
      raise "DB is not up... Aborting." unless  is_started?(host)
    end
    
    
    # Sets the replication grants according to the global variables (set by environment params)
    def set_replication_grants(slavecon)
      raise "Replication User and/or password variables not set!. Probably forgot to set them on the environment or rightscript?" if @rep_user == nil || @rep_pass == nil
      slavecon.exec("GRANT REPLICATION SLAVE ON *.* TO '#{@rep_user}'@'%' IDENTIFIED BY '#{@rep_pass}'")
      
      #TODO: Write it to postgresql.conf
    end
 
    # takes options for host, user, pass, query, and timeout in seconds
    # Returns the unmodified result of connection.query
    def do_query_with_terminate(options = {})
      [:user,:query].each do |s|
        raise "ERROR: do_query_with_terminate, argument error: missing #{s}" if options[s] == nil
      end
      timeout = options[:timeout] || RightScale::DBUtils::QueryTimeout
      host = options[:host] || "" # Localhost by default
      result = nil
      puts "running query: #{options[:query]}"
      puts "timeout: #{timeout}"
      puts "host: #{host}"
      puts "options: #{options.inspect}"
      SystemTimer.timeout_after(timeout) do
        conn = PGconn.open("host", nil, nil, nil, nil, "postgres", nil)        
        puts "Connected to host [#{host}]"
        result = conn.exec(options[:query])
        puts "Query completed."
      end
      return result
    end

    # It will try to flush the outstanding data and get a global lock on the DB so
    # that we have a stable and consistend disk image (i.e., to backup/snapshot)
    # This function takes a timeout and number of allowed attempts to aquire the lock.
    # returns PID of a process that holds the lock if it succeeds. Which means that 
    #             the flush has been made and the lock is helod by that "waiting" process.
    #             The caller must ensure that the resulting PID is killed, to release 
    #             the locks. One can use the function release_lock_from_helper() provided 
    #             Otherwise the process will never release them
    # returns nil if the locks couldn't be retrieved in the timeout specified,
    # for the given amount of attempts.
    def flush_and_lock_db( dbhost, user, password, timeout, max_attempts)
      got_lock_message = "GOT_LOCK"
      release_lock_message = "RELEASE_LOCK"
      procs = []
      rd_pipes = []
      wr_pipes = []
      successful = -1
      begin
        max_attempts.times do |round|     
          rd,wr = IO.pipe
          rd_pipes[round] = rd
          wr_pipes[round] = wr
          pid = fork do 
            begin
              rd.close
              #puts "This is a proc. Info: #{$$}"  
              conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)

              # Standby servers cannot run pg_start_backup since
              # they are in a constant state of 'recovery'.
              # Instead, we will just pause running xlogs and take snapshot.
              # When we resume running xlogs, we will run
              # pg_xlog_replay_resume.
              mastersuccess = detect_if_master?()
              if ( mastersuccess == true )              
                conn.exec("SELECT pg_start_backup('backup')")
              else
                conn.exec("SELECT pg_xlog_replay_pause()")
              end
              puts "proc #{$$} got the lock"
              wr.write(got_lock_message)
              # wait until be notified 
              begin 
                sleep(4) # we'll loop sleep while we await our fate (the parent to kill us)
                next
              rescue StandardError => e
                puts "Rescued something: "+e.to_s
                break # any other error and we're out...
              end while true
            ensure
              conn.finish if conn
            end
            exit(-1)
          end
          # Parent...attempting a trial round
          procs[round] = pid
          successful = check_pipes_for_success( procs, rd_pipes, timeout , got_lock_message)
          break if successful != nil
        end
        if successful != nil then
          puts "Process #{procs[successful]} has the lock. terminating others." 
          procs.each_index do |pidx|
            Process.kill("SIGKILL",procs[pidx]) unless pidx == successful
          end
          return procs[successful]
        else
          puts "No...couldn't get the locks in the end...terminating all helper processes"
          procs.each_index do |pidx|
            puts "killing PID #{procs[pidx]}"
            Process.kill("SIGKILL",procs[pidx])
          end
          return nil
        end
      ensure 
      end
    end

    # Function that will kill a process (helper) given a pid, and
    # therefore release the DB locks he was holding
    def release_lock_from_helper(pid)
      FileUtils.rm_rf(LOCK_PID_FILE)
      conn = PGconn.open("localhost", nil, nil, nil, nil, "postgres", nil)
      mastersuccess = detect_if_master?()

      # Standby servers cannot run pg_start_backup/pg_stop_backup since
      # they are in a constant state of 'recovery'.
      # We will just pause running xlogs and take snapshot, then
      # resume running xlogs.
      if ( mastersuccess == true )       
        conn.exec("SELECT pg_stop_backup()")
      else
        conn.exec("SELECT pg_xlog_replay_resume()")
      end
      conn.finish
      Process.kill("SIGKILL", pid)
    end

    ### Database manipulation 

    # Checks if the setup of a given host is in initial/pristine condition
    def is_db_pristine?( dbhost ) 
      res = `env PGCONNECT_TIMEOUT=30 psql -U postgres -qt -c "select count(*) from pg_catalog.pg_database d WHERE d.datname NOT IN ('postgres', 'template0', 'template1')"`.strip
      raise RemoteExecException.new(dbhost,$?,res) if $? != 0
      return res == "0"
    end
    
      
    def is_started?(host=nil)
      os_vals = execute_db_service_command( host , "status" )
      status_res = execute_db_service_command( host , "status" )
      (status_res =~ /#{os_vals[:pgsql_started_tag]}/ ||  status_res =~ /#{os_vals[:pgsql_started_tag]}/)
    end
    
    ########################## PRIVATE ##########################
    private
    
    # Tries to bring up the DB once (in case it's stopped)
    # Returns true for success (i.e., the DB is left running) or false if it couldn't be started)
    # There's a similar call (ensure_db_started) that tries to start it more than once
    def ensure_db_started_internal(host=nil)
      #host ="localhost" if host == nil
      execute_db_service_command( host , "start" )
      status_res = execute_db_service_command( host , "status" )
      return true if status_res =~ /Running clusters: \d+/ || status_res =~ /\s.+is running/
      execute_db_service_command( host , "start" )
      return true
    end
    
  end
end
