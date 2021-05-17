Keycloak.configure do |config|
  config.auth_server_url = ENV["SSO_AUTH_URL"]
  config.realm   = ''
  config.client_id   = ''
  config.client_secret   = ENV['SSO_CLIENT_SECRET']
  config.keycloak_controller = 'session'
  config.auth_callback_action = 'signin'
  config.cookie_key = 'KEYCLOAK_TOKEN'

  logger = Logger.new(STDOUT)
  logger.level = Logger::DEBUG
  logger.progname = 'Keycloak'
  logger.formatter = proc do |severity, time, progname, msg|
    "[#{progname}][#{severity}] #{time}: \n\t#{msg} \n\n"
  end
  config.logger     = logger
end