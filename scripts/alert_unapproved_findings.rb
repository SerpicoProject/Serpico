require './model/master.rb'

findings = TemplateFindings.all

fd = false
findings.each do |finding|
    if finding["approved"] == false
		puts "|+| Title: #{finding["title"]} (https://127.0.0.1:8443/master/findings/#{finding["id"]}/edit)"
		fd = true
	end
end

unless fd
	puts "|!| No Unapproved Findings Found"
end
