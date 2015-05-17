require 'rubygems'
require 'nokogiri'
require 'zipruby'

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

def parse_burp_xml(xml)
    vulns = Hash.new
    
    doc = Nokogiri::XML(File.open(xml))
    doc.css('//issues/issue').each do |issue|
        if issue.css('severity').text == "Medium"
            host = issue.css('host').text
            ip = issue.css('host').attr('ip')
            id = issue.css('type').text
            hostname = "#{ip} #{host}"
            if vulns[hostname]
                vulns[hostname] << id
            else 
                vulns[hostname] = []
                vulns[hostname] << id
            end
        end
    end
    return vulns
end
