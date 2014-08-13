#
# RightScale Tools
#
# Copyright RightScale, Inc. All rights reserved.
# All access and use subject to the RightScale Terms of Service available at
# http://www.rightscale.com/terms.php and, if applicable, other agreements
# such as a RightScale Master Subscription Agreement.

require 'logger'

# common helper methods (common to ALL)

module RightScale
  module Tools
    module Common
      
      @@logger = nil
      
      def logger=(l)
        @@logger = l
      end

      def logger
        if defined? Chef::Log
          # Use the Chef::Log if available
          @@logger = Chef::Log.logger
        elsif @@logger == nil
          # Log to STDOUT at info level if no logger defined
          @@logger = Logger.new(STDOUT)
          @@logger.level = Logger::INFO
        end
        @@logger
      end

      def log_info(message)
        logger.info(message)
      end

      def log_debug(message)
        logger.debug(message)
      end

      def execute(command, options = {})
        log_debug("Running command: #{command}")
        retry_num = options[:retry_num] ? options[:retry_num] : 0
        retry_sleep = options[:retry_sleep] ? options[:retry_sleep] : 60
        ignore_failure = options[:ignore_failure] ? options[:ignore_failure] : false
        debug = options[:debug] ? options[:debug] : false

        (retry_num + 1).times do |attempt|
          output = `#{command} 2>&1`
          if debug
            log_debug "running #{command}"
            log_debug "attempt #{attempt}"
            log_debug output
          else
            log_info "running #{command}"
            log_debug "attempt #{attempt}"
            log_info output
          end
          return output if $?.success? && options[:return_output]
          return true if $?.success?
          sleep retry_sleep unless retry_num == 0
        end
        raise "ERROR: command failed: #{command}" unless ignore_failure
        false
      end
    
      protected 
    
      # this will attempt to display any http response related information about the exception and simply
      # inspect the exception if none is available. optional display name will print any custom information.
      def display_exception(e, display_name=nil)
        log_info "CAUGHT EXCEPTION in: #{display_name}"
        log_info e.inspect
        puts e.backtrace 
        if e.respond_to?(:response)
          log_info e.response
          if e.response.respond_to?(:body)
            log_info "RESPONSE BODY: #{e.response.body}"
          end
        end
      end

      private

      def not_implemented
        caller[0] =~ /`(.*?)'/
        raise NotImplementedError, "#{$1} is not implemented on #{self.class}"
      end
    end
  end
end
