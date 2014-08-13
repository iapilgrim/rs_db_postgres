#
# RightScale Tools
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

require 'rubygems'
require 'system_timer'

module RightScale  
  # Just some convenience exception container for remote execution errors
  class RemoteExecException < RuntimeError 
    attr :exit_code, :message
    def initialize(remote_host, exit_code, message) 
      @host = remote_host || "localhost"
      @exit_code = exit_code
      @message = message
    end 
    
    def to_s
      return "Host:#@host Error:#@exit_code\n#@message"
    end
  end
  
  module DBUtils
    QueryTimeout = 120
    
    def initialize(params = {})
      ### Variables
      
      # if running outside runrightscripts.rb, this variable is unset.
      ENV['RS_DISTRO'] = `lsb_release -is`.chomp.downcase unless ENV['RS_DISTRO']
    end


    ### Miscelaneous  ###

    # Get the mount point of a device in a remote machine
    # or local machine is host is not specified (i.e., is nil)
    def get_mount_point( host, device )
      prefix = (host!=nil) ? "ssh #{host} ":""
      mount_line = `#{prefix} mount | grep '^#{device}'`
      raise RemoteExecException.new(host,$?,mount_line) if $? != 0
      if( mount_line.length == 0 )
        puts "Couldn't find the lvm volume mounted in  #{host}"
        Kernel.exit(-1)
      end
      # The directory comes on the third place in the mount output:
      # /dev/vg-data/lv-data on /mnt type ext3 (rw)
      return mount_line.split(/ /)[2]  
    end

    # Decide if two hosts are the same node by comparing
    # their ifconfig output
    # If one is nil, the information will be retrieved locally
    def same_machine?( host1, host2 )
      return true if host1 == host2
      prefix1 = (host1!=nil) ? "ssh #{host1} ":""
      prefix2 = (host2!=nil) ? "ssh #{host2} ":""
      ifconfig_cmd = "ifconfig eth0 | grep 'inet addr:'"
      host1_ifconfig_output = `#{prefix1} #{ifconfig_cmd}`
      raise RemoteExecException.new(host1,$?,host1_ifconfig_output) if $? != 0
      host2_ifconfig_output = `#{prefix2} #{ifconfig_cmd}`
      raise RemoteExecException.new(host2,$?,host2_ifconfig_output) if $? != 0
  
      return ( host1_ifconfig_output == host2_ifconfig_output )
    end

    # Given a hostname or IP, it connects to it and extracts the primary IP
    # If null, it gets the information locally
    def get_ip_from_ifconfig( host )
      prefix = (host!=nil) ? "ssh #{host} ":""
      ifconfig_cmd = "ifconfig eth0 | grep 'inet addr:'"
      ifconfig_output = `#{prefix} #{ifconfig_cmd}`
      ifconfig_output =~ /inet addr:([^\s]+).+/
      ip = $1
      raise RemoteExecException.new(host,$?,ifconfig_output) if $? != 0
      return ip
    end

    # It forces the acceptance of a remote host's ssh key. This is used to ensure
    # that subsequent ssh commands do not get stuck due to the interactive question
    # of accepting or rejecting.
    # WARNING: This poses a security thread...if keys are correctly setup this might
    # not be necessary
    def accept_ssh_key( host, user="root" )
      return unless host
      out = `ssh -o StrictHostKeyChecking=no #{user}@#{host} date`
      raise RemoteExecException.new(host,$?,out) if $? != 0
    end


    # Check if any of the passed pipes has written the magic cookie (got_lock contents)
    # denoting that he holds the table locks.
    # Does not read forever...uses non blocking reads and it returns after a maximum
    # of max_secs
    def check_pipes_for_success( procs, rd_pipes, max_sec , got_lock)
  
      init_sec = Time.now.to_i
      begin
        any_luck = -1;
        rd_pipes.each_index do |idx|
          begin
            result = rd_pipes[idx].read_nonblock( got_lock.length )
          rescue EOFError => ioe
            #If the pipe is dead, we're sure the process on the other side doesn't have the lock!
            puts "pipe for index #{idx} is dead: "+ioe.to_s
            next
          rescue Errno::EAGAIN  # we would block...so , we'll patiently wait
            next
          end
          if( result != nil && result == got_lock ) then
            return idx  
          else
            puts "We read something weird from pid #{procs[idx]} : [#{result}]"
          end
        end
        select(nil,nil,nil,0.1)
        #sleep(0.1) # let's sleep a bitjust to avoid a tight loop
      end while Time.now.to_i - init_sec < max_sec
      return nil;  
    end

    # Function that will kill a process (helper) given a pid, and 
    # therefore release the DB locks he was holding
    def release_lock_from_helper pid
      Process.kill("SIGKILL",pid)
    end

    def clean_directory(host, dir)  
      puts "Cleaning directory (#{dir})..."
      prefix = (host) ? "ssh #{host} ":""
      result = `#{prefix} rm -rf #{dir}/*`
      raise RemoteExecException.new(host,$?,"Error deleting dir (#{dir}): "+result) if $? != 0
    end    

    # Return a handle to an opened (and exclusively locked file).
    def get_locked_file( lockfile, timeout = 60 )
      cfg_file = File.open(lockfile,"r+")
      success = false
      timeout.times {
        if cfg_file.flock(File::LOCK_EX | File::LOCK_NB )
          success=true
          break
        end
        puts "Lockfile is locked...retrying..."
        sleep 1
      }
      raise "Couldn't acquire the lockfile..." unless success
      return cfg_file
    end
    
    
    ### LVM filesystem snapshot utilities #######################
    # Log into the machine and check if there's an already created snapshot 
    # (i.e., check if there's an existing lv with the name we use...)
    # It raises a RemoteExecException if there's an error executing the command
    # if host is nil, we'll check locally
    def previous_lvm_snapshot_exists?(host, lv_snapshot_name)
      # Use echo, to avoid getting the possible error code of a grep that doesn't match anything
      cmd = "lvs -o lv_name --noheadings"
      if host != nil then
        lvs_result=`ssh #{host} #{cmd}`
      else
        lvs_result=`#{cmd}`
      end
      raise RemoteExecException.new(host,$?,lvs_result) if $? != 0
  
      if lvs_result =~ /#{lv_snapshot_name}/
        return true
      else
        return false
      end
    end

    # Connect to the master and create an readonly snapshot of the volume where the
    # DB resides.
    # We use the LVM snapshot facilities to create an "instant" copy so we can avoid
    # interrupting the operation of the master for a long time.
    # We'll mount the snapshot on a directory in the root, with the same name as the
    # lvm snapshot volume. Also, we'll replicate the same structure on top of that
    # directory so that we can see the same paths of the original directory with 
    # respect to the original root.
    # For example, if the original lvm data dir was mounted on /mnt, we'll mount
    # the snapshot at /snapshotname/mnt. That way, from /snapshotname we see the
    # same structure with respect of the original disks
    # * dbbackup_name is the name of the snapshot to use (and therefore the directory 
    #   on which we'll mount it from the root)
    # If master is nil, we'll execute the snapshot locally
    def create_lvm_snapshot( master , dbbackup_name , lvm_data_mounted_on)
      err_label= "Error creating snapshot:\n"
  
      prefix = (master!=nil) ? "ssh #{master} ":""

      # The number of logical volumes, that is currently used for snapshot(s)
      num_of_curr_snapshots=`#{prefix} lvscan | grep -i snapshot | wc -l`
      raise RemoteExecException.new(master,$?,err_label+num_of_curr_snapshots) if $? != 0

      # Getting the information of vg size.0 and vg free.1
      vg_sizes_str=`#{prefix} vgs --nosuffix -o vg_name,vg_size,vg_free --noheadings --units m --separator '.' | grep vg-data | cut -d. -f 2,4`
      raise RemoteExecException.new(master,$?,err_label+vg_sizes_str) if $? != 0

      # Determine the min. alloc size of each physical volumn for small/large/xlarge
      pv_size = `uname -i`.chop == "i386" ? 10 : 25
      min_snap_size = `pvs --noheadings -o pv_name | wc -l`.to_i * pv_size

      # Calculate the max. alloc size (15% of lv size) that a snapshot can use
      vg_sizes = vg_sizes_str.split('.').collect {|n| n.to_f}
      max_alloc_snap = (vg_sizes[0] - vg_sizes[1]) * 0.15

      # If there already exists a snapshot, we use all the remaining space; else,
      # we use half
      snapshot_size = (num_of_curr_snapshots.to_i > 0) ? "100" : "50"

      # If the free size is more than enough for two snapshots, we don't want to
      # use all the space for it. We use only the max_alloc_size and further
      # convert that to %FREE
      snapshot_size =  (max_alloc_snap / vg_sizes[1] * 100).to_i if vg_sizes[1] > (max_alloc_snap + min_snap_size)

      puts "Creating a snapshot of size #{snapshot_size}% of what is free..."
      result = `#{prefix} lvcreate -l #{snapshot_size}%FREE -s -n #{dbbackup_name} /dev/vg-data/lv-data`
      raise RemoteExecException.new(master,$?,err_label+result) if $? != 0
      result = `#{prefix} mkdir -p /#{dbbackup_name}/#{lvm_data_mounted_on}`
      raise RemoteExecException.new(master,$?,err_label+result) if $? != 0  
  
      # For backwards compatibility mount the snapshot differently (old images might still use ext3...now we use xfs...)
      result = `#{prefix} mount -l -t ext3 | grep "on /mnt " || echo -n`
      raise RemoteExecException.new(master,$?,err_label+result) if $? != 0
  
      # If we found /mnt mounted as ext3....
      if result != nil && result!=""
        # We can directly mount it read only
        result = `#{prefix} mount -o ro /dev/vg-data/#{dbbackup_name} /#{dbbackup_name}/#{lvm_data_mounted_on}`
        raise RemoteExecException.new(master,$?,err_label+result) if $? != 0
      else # If it's not ext3 .. we assume it's xfs..
        #First mount RW, in case it needs log repairs
        result = `#{prefix} mount -o nouuid /dev/vg-data/#{dbbackup_name} /#{dbbackup_name}/#{lvm_data_mounted_on}`
        raise RemoteExecException.new(master,$?,err_label+result) if $? != 0
        #Then remount it RO to ensure that nobody writes to it while we're doing the backup
        result = `#{prefix} mount -o remount,ro,nouuid /dev/vg-data/#{dbbackup_name} /#{dbbackup_name}/#{lvm_data_mounted_on}`
        raise RemoteExecException.new(master,$?,err_label+result) if $? != 0 
      end
      puts "snapshot created."
    end 

    # Delete an existing lvm snapshot in a remote or local host
    def delete_lvm_snapshot( host, dbbackup_name )
      prefix = (host!=nil) ? "ssh #{host} ":""
      err_label= "Error deleting snapshot:\n"
      dev_name = "/dev/vg-data/#{dbbackup_name}"
      puts "Deleting device #{dev_name} mounted on "
        
      puts "EXECUTING: #{prefix} mount | grep '#{dbbackup_name}' 2>&1"
      mountres=`#{prefix} mount | grep '#{dbbackup_name}' 2>&1`
      puts "RESULT=[#{mountres}]"
      puts "CODE=#{$?}"
      if mountres != "" 
        puts "snapshot is mounted...unmounting"
        result=""
        max_umount_rounds = 30;
        max_umount_rounds.times do |round|
          result = `#{prefix} umount #{dev_name} 2>&1`
          break if $? == 0 || round > max_umount_rounds || ! result =~ /device is busy/
          puts "couldn't umount yet (#{result})...retrying"
          sleep 1
        end
      end
      errcode = $?
      # Ensure the snapshot is deleted if it can be (without raising exception for it if it fails)
      remresult = `#{prefix} lvremove -f #{dev_name}`
      puts "Error deleting snapshot: #{remresult}" if $? != 0
  
      raise RemoteExecException.new(host,errcode,err_label+remresult) if errcode != 0

      puts "Snapshot deleted."
   
    end
  end
end
