require 'sinatra'
require './config'
### Basic Routes

# Used for 404 responses
not_found do
  "Sorry, I don't know this page."
end

# Error catches
error do
  if settings.show_exceptions
    'Error!' + env['sinatra.error'].name
  else
    'Error!! Check the process dump for the error or turn show_exceptions on to show in the web interface.'
  end
end

# Run a session check on every route
['/info', '/reports/*', '/report/*', '/', '/logout', '/admin/*', '/master/*', '/mapping/*'].each do |path|
  before path do
    next if request.path_info == '/reports/list'
    redirect '/reports/list' unless valid_session?
  end
end

before '/master/*' do
  redirect to('/no_access') unless is_administrator?
end

before '/mapping/*' do
  redirect to('/no_access') unless is_administrator?
end
#######

get '/' do
  redirect to('/reports/list')
end

get '/login' do
  redirect to('/reports/list')
end

# Handles the consultant information settings
get '/info' do
  @user = User.first(username: get_username)

  unless @user
    @user = User.new
    @user.auth_type = 'AD'
    @user.username = get_username
    @user.type = 'User'
    @user.save
  end

  haml :info
end

# Save the consultant information into the database
post '/info' do
  user = User.first(username: get_username)

  unless user
    user = User.new
    user.auth_type = 'AD'
    user.username = get_username
    user.type = 'User'
  end

  user.consultant_email = params[:email]
  user.consultant_phone = params[:phone]
  user.consultant_title = params[:title]
  user.consultant_name = params[:name]
  user.consultant_company = params[:company]
  user.save

  serpico_log('Consultant info updated')
  redirect to('/info')

end

# Handles password reset
get '/reset' do
  redirect '/reports/list' unless valid_session?

  haml :reset
end

# Handles the password reset
post '/reset' do
  redirect '/reports/list' unless valid_session?

  # grab the user info
  user = User.first(username: get_username)

  # check if they are an LDAP user
  if user.auth_type != 'Local'
    return 'You are an LDAP user. You cannot change your password.'
  end

  # check if the password is greater than 3 chars. legit complexity rules =/
  #   TODO add password complexity requirements
  if params[:new_pass].size < 4
    return 'Srsly? Your password must be greater than 3 characters.'
  end

  if params[:new_pass] != params[:new_pass_confirm]
    return 'New password does not match.'
  end

  unless User.authenticate(user.username, params[:old_pass])
    return 'Old password is incorrect.'
  end

  user.update(password: params[:new_pass])
  @message = 'success'
  serpico_log('Password successfully reset')
  haml :reset
end

post '/login' do
  user = User.first(username: params[:username])

  if user && (user.auth_type == 'Local')
    usern = User.authenticate(params['username'], params['password'])

    if usern && session[:session_id]
      # replace the session in the session table
      # TODO : This needs an expiration, session fixation
      @del_session = Sessions.first(username: usern.to_s)
      @del_session.destroy if @del_session
      @curr_session = Sessions.create(username: usern.to_s, session_key: session[:session_id].to_s)
      @curr_session.save
      serpico_log("Successful local login")

    end
  elsif user
    if Config['ldap'].to_s == 'true'
      # try AD authentication
      usern = params[:username]
      data = url_escape_hash(request.POST)
      redirect to('/') if (usern == '') || (params[:password] == '')

      user = "#{Config['ldap_domain']}\\#{data['username']}"
      ldap = Net::LDAP.new host: (Config['ldap_dc']).to_s, port: 636, encryption: :simple_tls, auth: { method: :simple, username: user, password: params[:password] }

      if ldap.bind
        # replace the session in the session table
        @del_session = Sessions.first(username: usern.to_s)
        @del_session.destroy if @del_session
        @curr_session = Sessions.create(username: usern.to_s, session_key: session[:session_id].to_s)
        @curr_session.save

        serpico_log('Successful LDAP login')
      end
    end
  end

  redirect to('/')
end

## We use a persistent session table, one session per user; no end date
get '/logout' do
  #hack to display username in log after session destroyed
  user = User.first(:username => get_username)
  if session[:session_id]
    sess = Sessions.first(session_key: session[:session_id])
    sess.destroy if sess
  end

  serpico_log('User #{user.username} logged out')
  redirect to('/')
end

# rejected access (admin functionality)
get '/no_access' do
  serpico_log('Low priv user tried to access admin resource')
  return 'Sorry. You Do Not have access to this resource.'
end
