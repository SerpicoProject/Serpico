require 'rubygems'
require 'nokogiri'
require './model/master'
require 'msfrpc-client'

# For now, we need this to clean up import text a bit
def clean(text)
  return unless text

  text = text.squeeze(' ')
  text = text.gsub('<br>', "\n")
  text = text.gsub('<p>', "\n")
  text = text.gsub('<description>', '')
  text = text.gsub('</description>', '')
  text = text.gsub('<solution>', '')
  text = text.gsub('</solution>', '')
  text = text.gsub('<see_also>', '')
  text = text.gsub('</see_also>', '')
  text = text.gsub("<plugin_output>\n\n", '') # remove leading newline characters from nessus plugin output too!
  text = text.gsub("<plugin_output>\n", '') # remove leading newline character from nessus plugin output too!
  text = text.gsub('<plugin_output>', '')
  text = text.gsub('</plugin_output>', '')

  # burp stores html and needs to be removed, TODO better way to handle this
  text = text.gsub('</p>', '')
  text = text.gsub('<li>', "\n")
  text = text.gsub('</li>', '')
  text = text.gsub('<ul>', "\n")
  text = text.gsub('</ul>', '')
  text = text.gsub('<table>', '')
  text = text.gsub('</table>', '')
  text = text.gsub('<td>', "\n")
  text = text.gsub('</td>', '')
  text = text.gsub('<tr>', '')
  text = text.gsub('</tr>', '')
  text = text.gsub('<b>', '')
  text = text.gsub('</b>', '')
  text = text.gsub('<![CDATA[', '')
  text = text.gsub(']]>', '')
  text = text.gsub("\n\n", "\n")

  text = text.gsub("\n", "\r\n")

  text_ = url_escape_hash('a' => text)
  text = text_['a']

  text
end

def uniq_findings(findings)
  vfindings = []
  # this gets a uniq on the findings and groups hosts, could be more efficient
  findings.each do |single|
    # check if the finding has been added before
    exists = vfindings.detect { |f| f['title'] == single.title }

    if exists
      # get the index
      i = vfindings.index(exists)
      exists.affected_hosts = clean(exists.affected_hosts + ", #{single.affected_hosts}")
      if exists.notes
        exists.notes = exists.notes + "<paragraph></paragraph><paragraph></paragraph>#{single.notes}"
      end
      vfindings[i] = exists
    else
      vfindings << single
    end
  end
  vfindings
end

# when a finding is imported the score, must be nulled for CVSS/CVSS3/DREAD
def provide_null_score(finding)
  finding.damage = 1
  finding.reproducability = 1
  finding.exploitability = 1
  finding.affected_users = 1
  finding.discoverability = 1
  finding.dread_total = 1
  finding.nist800_total = 0

  finding.cvss_total = 0

  finding
end

def get_vulns_from_msf(rpc, workspace)
  res = rpc.call('console.create')

  vulns = {}

  rpc.call('db.set_workspace', workspace)

  # get vulns TODO:find a better way to handle large amount of vulns
  res = rpc.call('db.vulns', limit: 9000)
  res.each do |v|
    v[1].each do |item|
      ids = []
      item['refs'].split(',').each do |i|
        ids << i
      end
      vulns[item['host']] = [] unless vulns[item['host']]
      ids.each do |id|
        vulns[item['host']] << id
      end
    end
  end
  vulns
end

def parse_nessus_xml(xml, threshold)
  vulns = {}
  findings = []
  items = []

  doc = Nokogiri::XML(xml)

  doc.css('//ReportHost').each do |hostnode|
    host = hostnode['name'] unless hostnode['name'].nil?
    hostnode.css('ReportItem').each do |itemnode|
      next unless itemnode['severity'] >= threshold

      # create a temporary finding object
      finding = Findings.new
      finding.title = itemnode['pluginName'].to_s
      finding.overview = clean(itemnode.css('description').to_s)
      finding.remediation = clean(itemnode.css('solution').to_s)

      # can this be inherited from an import properly?
      finding.type = 'Imported'
      finding.risk = itemnode['severity']
      finding = provide_null_score(finding)
      finding.affected_hosts = hostnode['name']
      if itemnode.css('plugin_output')
        finding.notes = hostnode['name'] + ' (' + itemnode['protocol'] + ' port ' + itemnode['port'] + '):' + clean(itemnode.css('plugin_output').to_s)
      end

      finding.references = clean(itemnode.css('see_also').to_s)

      findings << finding
      items << itemnode['pluginID'].to_s
    end
    vulns[host] = items
    items = []
  end

  vulns['findings'] = uniq_findings(findings)
  vulns
end

def parse_burp_xml(xml)
  vulns = {}
  findings = []
  vulns['findings'] = []

  doc = Nokogiri::XML(xml)
  doc.css('//issues/issue').each do |issue|
    next unless issue.css('severity').text
    # create a temporary finding object
    finding = Findings.new
    finding.title = clean(issue.css('name').text.to_s)
    finding.overview = clean(issue.css('issueBackground').text.to_s + issue.css('issueDetail').text.to_s)
    finding.remediation = clean(issue.css('remediationBackground').text.to_s)

    finding.risk = if issue.css('severity').text == 'Low'
                     1
                   elsif issue.css('severity').text == 'Medium'
                     2
                   elsif issue.css('severity').text == 'High'
                     3
                   else
                     1
                   end

    finding = provide_null_score(finding)

    finding.type = 'Web Application'

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

  vulns['findings'] = uniq_findings(findings)
  vulns
end
