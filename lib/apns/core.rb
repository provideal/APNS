module APNS
  require 'socket'
  require 'openssl'
  require 'json'

  @host = 'gateway.sandbox.push.apple.com'
  @port = 2195
  # openssl pkcs12 -in mycert.p12 -out client-cert.pem -nodes -clcerts
  @pem = nil # this should be the path of the pem file not the contentes
  @pass = nil

  class << self
    attr_accessor :host, :pem, :port, :pass
  end

  def self.send_notification(device_token, message)
    sock, ssl = self.open_connection
    begin
      ssl.write(self.packaged_notification(device_token, message))
    ensure
      ssl.close
      sock.close
    end
  end

  def self.send_notifications(notifications)
    sock, ssl = self.open_connection
    begin
      notifications.each do |n|
        ssl.write(n.packaged_notification)
      end
    ensure
      ssl.close
      sock.close
    end
  end

  def self.feedback
    sock, ssl = self.feedback_connection
    apns_feedback = []

    begin
      while line = sock.gets   # Read lines from the socket
        line.strip!
        f = line.unpack('N1n1H140')
        apns_feedback << [Time.at(f[0]), f[2]]
      end
    ensure
      ssl.close
      sock.close
    end

    return apns_feedback
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

  def self.open_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
    raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

    sock         = TCPSocket.new(self.host, self.port)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

  def self.feedback_connection
    raise "The path to your pem file is not set. (APNS.pem = /path/to/cert.pem)" unless self.pem
    raise "The path to your pem file does not exist!" unless File.exist?(self.pem)

    context      = OpenSSL::SSL::SSLContext.new
    context.cert = OpenSSL::X509::Certificate.new(File.read(self.pem))
    context.key  = OpenSSL::PKey::RSA.new(File.read(self.pem), self.pass)

    fhost = self.host.gsub!('gateway','feedback')
    puts fhost

    sock         = TCPSocket.new(fhost, 2196)
    ssl          = OpenSSL::SSL::SSLSocket.new(sock,context)
    ssl.connect

    return sock, ssl
  end

end
