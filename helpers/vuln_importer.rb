require 'rubygems'
require 'nokogiri'

def parse_nessus_xml(xml)
    vulns = Hash.new
    items = Array.new

    doc = Nokogiri::XML(xml)

    doc.css("//ReportHost").each do |hostnode|
        if (hostnode["name"] != nil)
            host = hostnode["name"]
        end
        hostnode.css("ReportItem").each do |itemnode|
            if (itemnode["port"] != "0" && itemnode["severity"] > "1")
                items << itemnode['pluginID'].to_s()
            end
        end
        vulns[host] = items
        items = []
    end
    return vulns
end
