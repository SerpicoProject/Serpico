require 'rubygems'
require './model/master.rb'

findings = TemplateFindings.all

findings.each do |finding|
     finding["approved"] = true
     finding.save 	
end
