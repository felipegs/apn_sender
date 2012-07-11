require 'socket'
require 'openssl'
require 'resque'

module APN
  module Connection
    # APN::Connection::Base takes care of all the boring certificate loading, socket creating, and logging
    # responsibilities so APN::Sender and APN::Feedback and focus on their respective specialties.
    module Base
      attr_accessor :opts, :logger
      attr_accessor :connections, :certificates

      def initialize(opts = {})
        @opts = opts
        setup_logger
        log(:info, "APN::Sender initializing. Establishing connections first...") if @opts[:verbose]
        setup_paths
        @connections = {}
        @certificates = {}
        super(APN::QUEUE_NAME) if self.class.ancestors.include?(Resque::Worker)
      end

      def setup_connection(full_cert_path)
        setup_certificate(full_cert_path)
        @connections[full_cert_path] ||= {}
        log_and_die("Trying to open half-open connection") if @connections[full_cert_path][:socket] || @connections[full_cert_path][:socket_tcp]

        ctx = OpenSSL::SSL::SSLContext.new
        ctx.cert = OpenSSL::X509::Certificate.new(@certificates[full_cert_path][:apn_cert])

        ctx.key = OpenSSL::PKey::RSA.new(@certificates[full_cert_path][:apn_cert])

        @connections[full_cert_path][:socket_tcp] = TCPSocket.new(apn_host, apn_port)
        @connections[full_cert_path][:socket] = OpenSSL::SSL::SSLSocket.new(@connections[full_cert_path][:socket_tcp], ctx)
        @connections[full_cert_path][:socket].sync = true
        @connections[full_cert_path][:socket].connect
      rescue SocketError => error
        log_and_die("Error with connection to #{apn_host}: #{error}")
      end

      def socket(full_cert_path)
        @connections[full_cert_path] ||= {}
        setup_connection(full_cert_path) unless  @connections[full_cert_path][:socket]
        @connections[full_cert_path][:socket]
      end

      protected
      def setup_logger
        @logger = if defined?(Merb::Logger)
                    Merb.logger
                  elsif defined?(::Rails.logger)
                    ::Rails.logger
                  end
        @logger ||= Logger.new(STDOUT)
      end

      alias_method(:resque_log, :log) if defined?(log)

      def log(level, message = nil)
        level, message = 'info', level if message.nil? # Handle only one argument if called from Resque, which expects only message

        resque_log(message) if defined?(resque_log)
        return false unless self.logger && self.logger.respond_to?(level)
        self.logger.send(level, "#{Time.now}: #{message}")
      end

      # Log the message first, to ensure it reports what went wrong if in daemon mode.
      # Then die, because something went horribly wrong.
      def log_and_die(msg)
        log(:fatal, msg)
        raise msg
      end

      def apn_production?
        @opts[:environment] && @opts[:environment] != '' && :production == @opts[:environment].to_sym
      end

      def setup_paths
        @opts[:environment] ||= ::Rails.env if defined?(::Rails.env)
      end

      def teardown_connection(full_cert_path)
        log(:info, "Closing connections...") if @opts[:verbose]

        begin
          @connections[full_cert_path][:socket].close if @connections[full_cert_path][:socket]
        rescue Exception => e
          log(:error, "Error closing SSL Socket: #{e}")
        end

        begin
          @connections[full_cert_path][:socket_tcp].close if  @connections[full_cert_path][:socket_tcp]
        rescue Exception => e
          log(:error, "Error closing TCP Socket: #{e}")
        end
      end

      def teardown_all_connections
        @connections.each_key do |key|
          teardown_connection(key)
        end
      end

      private
      def setup_certificate(full_cert_path)

        unless File.exists?(full_cert_path)
          log(:error, "Please specify correct :full_cert_path. No apple push notification certificate found in: #{full_cert_path}")
          raise CertificateNotFound
        end
        @certificates[full_cert_path] = {}
        @certificates[full_cert_path][:apn_cert] ||= File.read(full_cert_path)
      end

      class CertificateNotFound < RuntimeError
      end

    end
  end
end
