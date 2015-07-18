require 'rubygems'
require 'nokogiri'
require 'zipruby'
require './model/master'

# For now, we need this to clean up import text a bit
def clean(text)
    return unless text

    text = text.gsub("\n", "<br>")
    text = text.gsub(/\s+/, " ")
    text = text.gsub("<br>", "\n")
    text = text.gsub("\n\n", "\n")
    text = text.gsub("<description>","")
    text = text.gsub("</description>","")
    text = text.gsub("<solution>","")
    text = text.gsub("</solution>","")

    return text
end

def parse_nessus_xml(xml)
    vulns = Hash.new
    findings = Array.new
    items = Array.new

    doc = Nokogiri::XML(xml)

    doc.css("//ReportHost").each do |hostnode|
        if (hostnode["name"] != nil)
            host = hostnode["name"]
        end
        hostnode.css("ReportItem").each do |itemnode|
            if (itemnode["port"] != "0" && itemnode["severity"] > "1")

                # create a temporary finding object
                finding = Findings.new()
                finding.title = itemnode['pluginName'].to_s()
                finding.overview = clean(itemnode.css("description").to_s)
                finding.remediation = clean(itemnode.css("solution").to_s)

                # hardcode the risk, the user should fix this
                finding.risk = 0
                finding.damage = 0
                finding.reproducability = 0
                finding.exploitability = 0
                finding.affected_users = 0
                finding.discoverability = 0
                finding.dread_total = 0

                findings << finding

                items << itemnode['pluginID'].to_s()
            end
        end
        vulns[host] = items
        items = []
    end

    vulns["findings"] = findings.uniq
    return vulns
end

def parse_burp_xml(xml)
    vulns = Hash.new

    doc = Nokogiri::XML(xml)
    doc.css('//issues/issue').each do |issue|
        if issue.css('severity').text
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
