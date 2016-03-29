require 'rubygems'
require 'nokogiri'
require 'zipruby'
require './model/master'

# For now, we need this to clean up import text a bit
def clean(text)
    return unless text

    text = text.squeeze(" ")
    text = text.gsub("<br>", "\n")
    text = text.gsub("<p>", "\n")
    text = text.gsub("<description>","")
    text = text.gsub("</description>","")
    text = text.gsub("<solution>","")
    text = text.gsub("</solution>","")
    text = text.gsub("<see_also>","")
    text = text.gsub("</see_also>","")
    text = text.gsub("<plugin_output>\n\n","")    #remove leading newline characters from nessus plugin output too!
    text = text.gsub("<plugin_output>\n","")    #remove leading newline character from nessus plugin output too!
    text = text.gsub("<plugin_output>","")
    text = text.gsub("</plugin_output>","")

    # burp stores html and needs to be removed, TODO better way to handle this
    text = text.gsub("</p>", "")
    text = text.gsub("<li>", "\n")
    text = text.gsub("</li>", "")
    text = text.gsub("<ul>", "\n")
    text = text.gsub("</ul>", "")
    text = text.gsub("<table>", "")
    text = text.gsub("</table>", "")
    text = text.gsub("<td>", "\n")
    text = text.gsub("</td>", "")
    text = text.gsub("<tr>", "")
    text = text.gsub("</tr>", "")
    text = text.gsub("<b>", "")
    text = text.gsub("</b>", "")
    text = text.gsub("<![CDATA[","")
    text = text.gsub("]]>","")
    text = text.gsub("\n\n","\n")

    text = text.gsub("\n","\r\n")

    text_ = url_escape_hash({'a' => text})
    text = text_['a']

    return text
end

def uniq_findings(findings)
    vfindings = []
    # this gets a uniq on the findings and groups hosts, could be more efficient
    findings.each do |single|
        # check if the finding has been added before
        exists = vfindings.detect {|f| f["title"] == single.title }

        if exists
            #get the index
            i = vfindings.index(exists)
            exists.affected_hosts = clean(exists.affected_hosts+", #{single.affected_hosts}")
            if exists.notes
                exists.notes = exists.notes+"<paragraph></paragraph><paragraph></paragraph>#{single.notes}"
            end
            vfindings[i] = exists
        else
            vfindings << single
        end
    end
    return vfindings
end

def parse_nessus_xml(xml,threshold)
    vulns = Hash.new
    findings = Array.new
    items = Array.new

    doc = Nokogiri::XML(xml)

    doc.css("//ReportHost").each do |hostnode|
        if (hostnode["name"] != nil)
            host = hostnode["name"]
        end
        hostnode.css("ReportItem").each do |itemnode|
            if (itemnode["port"] != "0" && itemnode["severity"] >= threshold)

                # create a temporary finding object
                finding = Findings.new()
                finding.title = itemnode['pluginName'].to_s()
                finding.overview = clean(itemnode.css("description").to_s)
                finding.remediation = clean(itemnode.css("solution").to_s)

                # can this be inherited from an import properly?
                finding.type = "Imported"

                finding.risk = itemnode["severity"]

                # hardcode the DREAD score, the user should fix this
                finding.damage = 1
                finding.reproducability = 1
                finding.exploitability = 1
                finding.affected_users = 1
                finding.discoverability = 1
                finding.dread_total = 1

                finding.affected_hosts = hostnode["name"]

                if itemnode.css("plugin_output")
                    finding.notes = hostnode["name"]+" ("+itemnode["protocol"]+ " port " + itemnode["port"]+"):"+clean(itemnode.css("plugin_output").to_s)
                end

                finding.references = clean(itemnode.css("see_also").to_s)

                findings << finding
                items << itemnode['pluginID'].to_s()
            end
        end
        vulns[host] = items
        items = []
    end

    vulns["findings"] = uniq_findings(findings)
    return vulns
end

def parse_burp_xml(xml)
    vulns = Hash.new
    findings = Array.new
    vulns["findings"] = []

    doc = Nokogiri::XML(xml)
    doc.css('//issues/issue').each do |issue|
        if issue.css('severity').text
            # create a temporary finding object
            finding = Findings.new()
            finding.title = clean(issue.css('name').text.to_s())
            finding.overview = clean(issue.css('issueBackground').text.to_s()+issue.css('issueDetail').text.to_s())
            finding.remediation = clean(issue.css('remediationBackground').text.to_s())

            if issue.css('severity').text == 'Low'
                finding.risk = 1
            elsif issue.css('severity').text == 'Medium'
                finding.risk = 2
            elsif issue.css('severity').text =='High'
                finding.risk = 3
            else
                finding.risk = 1
            end

            # hardcode the DREAD score, the user assign the risk
            finding.damage = 1
            finding.reproducability = 1
            finding.exploitability = 1
            finding.affected_users = 1
            finding.discoverability = 1
            finding.dread_total = 1
            finding.type = "Web Application"

            findings << finding

            host = issue.css('host').text
            ip = issue.css('host').attr('ip')
            id = issue.css('type').text
            hostname = "#{ip} #{host}"

            finding.affected_hosts = "#{host} (#{ip})"

            if vulns[hostname]
                vulns[hostname] << id
            else
                vulns[hostname] = []
                vulns[hostname] << id
            end
        end
    end

    vulns["findings"] = uniq_findings(findings)
    return vulns
end
