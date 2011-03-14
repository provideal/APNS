module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts

  @gateway_host  = 'gateway.sandbox.push.apple.com'
  @gateway_port  = 2195
  @feedback_host = 'feedback.sandbox.push.apple.com'
  @feedback_port = 2196
  @pem           = nil # this should be the path of the pem file not the contentes
  @pass          = nil

  class << self
    attr_accessor :gateway_host, :gateway_port, :feedback_host, :feedback_port, :pem, :pass
  end

  def self.send_notification(device_token, message)
    sock, ssl = self.gateway_connection
    begin
      ssl.write(self.packaged_notification(device_token, message))
    ensure
      ssl.close
      sock.close
    end
  end

  def self.send_notifications(notifications)
    sock, ssl = self.gateway_connection
    begin
      notifications.each do |n|
        ssl.write(n.packaged_notification)
      end
    ensure
      ssl.close
      sock.close
    end
  end

  def self.feedback(&block)
    sock, ssl = self.feedback_connection
    tokens = []

    begin
      while line = sock.gets
        payload = line.strip.unpack('N1n1H140')
        tokens << {:device_token => payload[2], :updated_at => Time.at(payload[0])} if (payload and payload.length == 3)
      end
    ensure
      ssl.close
      sock.close
    end

    tokens.each { |token| yield token } if block_given?

    tokens
  end

  protected

  def self.packaged_notification(device_token, message)
    pt = self.packaged_token(device_token)
    pm = self.packaged_message(message)
    [0, 0, 32, pt, 0, pm.size, pm].pack("ccca*cca*")
  end

  def self.packaged_token(device_token)
    [device_token.gsub(/[\s|<|>]/,'')].pack('H*')
  end

  def self.packaged_message(message)
    if message.is_a?(Hash)
      apns_from_hash(message)
    elsif message.is_a?(String)
      '{"aps":{"alert":"'+ message + '"}}'
    else
      raise "Message needs to be either a hash or string"
    end
  end

  def self.apns_from_hash(hash)
    other = hash.delete(:other)
    aps = {'aps'=> hash }
    aps.merge!(other) if other
    aps.to_json
  end

  def self.gateway_connection
    self.connection(self.gateway_host, self.gateway_port)
  end

  def self.feedback_connection
    self.connection(self.feedback_host, self.feedback_port)
  end

  def self.connection(host, port)
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
    raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

    sock = TCPSocket.new(host, port)
    ssl = OpenSSL::SSL::SSLSocket.new(sock, context)
    ssl.connect

    return sock, ssl
  end

end
