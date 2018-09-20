require './helpers/vuln_importer'
require './helpers/helper'

# import_odle(data)
#
# Input: JSON object parsed from an XML using odle
#     e.g. data = JSON.parse(Nessus.new().parse(File.open(scan_xml),"0"))
#
# Note: format from odle data is:
#   An array of hosts with the tuple [host_location,[{JSON_OBJECT_OF_FINDING_DATA}]]
#   For example, host 1's title would be data[0][1][0]['title']
#
# @return: Returns an array of findings

def import_odle(data)
  vulns = {}
  findings = []

  data.each do |host|
    next unless host[1][0]

    host_d = host[1][0]

    finding = Findings.new
    finding.title = host_d['title']
    finding.overview = clean(host_d['overview'])
    finding.remediation = clean(host_d['remediation'])
    finding.type = 'Imported'
    finding.risk = clean(host_d['severity'])
    finding = provide_null_score(finding)
    finding.affected_hosts = host[0]
    finding.notes = clean(host_d['notes'])
    finding.references = clean(host_d['see_also'])

    findings << finding
  end

  vulns['findings'] = uniq_findings(findings)
  vulns
end
