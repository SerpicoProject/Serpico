require 'sinatra'
require './config'

##### Simple API Components - Read-Only for now


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
