require 'sinatra'

##### Simple API Components - Read-Only for now

config_options = JSON.parse(File.read('./config.json'))

# returns an API session key
post '/v1/session' do
  return auth(params[:username], params[:password])
end

# returns all reports available to the user, requires Session Key
post '/v1/reports' do
  return 'Please provide the API session' unless params[:session]
  return "Session is not valid \n" unless Sessions.is_valid?(params[:session])

  # use implicit session methods
  session[:session_id] = params[:session]

  reports = if params[:report_id]
              [get_report(params[:report_id])]
            else
              Reports.all
            end

  return '{}' if reports.first.nil?

  if is_administrator?
    return reports.to_json
  else
    # return reports owned by user
    data = []
    i = 0
    reports.each do |r|
      report = get_report(r.id)
      if report
        data[i] = report
        i += 1
      end
    end
    return data.to_json
  end

  return data
end

# returns finding based on report id, requires Session Key
post '/v1/findings' do
  return 'Please provide the API session' unless params[:session]
  return 'Session is not valid' unless Sessions.is_valid?(params[:session])
  return 'Please provide a report_id' unless params[:report_id]

  # use implicit session methods
  session[:session_id] = params[:session]

  report = get_report(params[:report_id])

  if report.nil?
    return '|-| Access rejected to report or report_id does not exist'
  end

  # Query for the findings that match the report_id
  findings = Findings.all(report_id: params[:report_id])

  return findings.to_json
end

# add a new finding
post '/v1/findings/new' do
  return 'Please provide the API session' unless params[:session]
  return 'Session is not valid' unless Sessions.is_valid?(params[:session])
  return 'Please provide a report_id' unless params[:report_id]

  # use implicit session methods
  session[:session_id] = params[:session]

  report = get_report(params[:report_id])

  if report.nil?
    return '|-| Access rejected to report or report_id does not exist'
  end

  data = url_escape_hash(request.POST)
  #data = request.POST

  #@report = get_report(id)
  #return 'No Such Report' if @report.nil?

  if report.scoring.casecmp('dread').zero?
    data['dread_total'] = data['damage'].to_i + data['reproducability'].to_i + data['exploitability'].to_i + data['affected_users'].to_i + data['discoverability'].to_i
    data = dread(Data)
  elsif report.scoring.casecmp('cvss').zero?
    data = cvss(data, false)
  elsif report.scoring.casecmp('cvssv3').zero?
    data = cvss(data, true)
  elsif(report.scoring.downcase == "nist800")
    # call nist800 helper function
    data = nist800(data)
  elsif(report.scoring.downcase == "risk")
    data = risk(data)
  end

  data['report_id'] = report.id

  data.delete('session')

  #data = url_escape_hash(request.POST)
  finding = Findings.new(data)
  finding.save

  # because of multiple scores we need to make sure all are set
  # => leave it up to the user to make the calculation if they switch mid report

  finding.dread_total = 0 if finding.dread_total.nil?
  finding.nist800_total = 0 if finding.nist800_total == nil
  finding.cvss_total = 0 if finding.cvss_total.nil?
  finding.risk = 0 if finding.risk.nil?
  finding.save

  return finding.to_json

end

