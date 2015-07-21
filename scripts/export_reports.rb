require './model/master.rb'
require 'json'

if ARGV.size < 1
	puts "|!| usage: export_reports.rb [id] [-d]\n"
	puts "\tThis script can be used to backup a large number of reports. Note, it does not save attachments."
	exit
end

id = ARGV[0]
puts "|+| Exporting all reports before id #{id}"

del = ARGV[1]
puts "|!| Deleting after export" if del

0.upto(id.to_i) do |temp|
	json = {}

	report = Reports.first(:id => temp)

	# bail without a report
	if not report
		puts "|!| report #{temp} does not exist, skipping"
	end
	next unless report

	puts "|+| exporting #{temp} to tmp/report_#{temp}.JSON"

	# add the report
	json["report"] = report

	# add the findings
	findings = Findings.all(:report_id => temp)
	json["findings"] = findings

	local_filename = "./tmp/report_#{temp}.json"
	File.open(local_filename, 'w') {|f| f.write(JSON.pretty_generate(json)) }

	if del
		puts "|!| deleting report #{temp}"
		report.destroy
		findings.destroy
	end
	report = ""
	findings = ""

end
