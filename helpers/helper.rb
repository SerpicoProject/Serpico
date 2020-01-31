require 'rubygems'
require 'zip'

# Log a message including the user and the time
def serpico_log(msg)
  user = User.first(username: get_username)
  uname = if user
            user.username
          else
            'unknown user'
          end
  if settings.logger_out
    settings.logger_out.puts "|+| [#{DateTime.now.strftime('%d/%m/%Y %H:%M')}] #{msg} : #{uname}"
  else
    puts "|+| [#{DateTime.now.strftime('%d/%m/%Y %H:%M')}] #{msg} : #{uname}"
  end
end

# Log a message globally, not attached to a user
def server_log(msg)
  if settings && settings.logger_out
    settings.logger_out.puts "|+| [#{DateTime.now.strftime('%d/%m/%Y %H:%M')}] #{msg} : SERVER_LOG"
  else
    puts "|+| [#{DateTime.now.strftime('%d/%m/%Y %H:%M')}] #{msg} : SERVER_LOG"
  end
end

def docx_modify(rand_file, docx_xml, fil_r)
  Zip::File.open(rand_file) do |zipfile|
    zipfile.get_output_stream(fil_r) { |f| f.write(docx_xml) }
  end
end

def find_headers_footers(docx)
  header_footer = []

  Zip::File.open(docx) do |zip|
    i = 1
    until zip.find_entry("word/header#{i}.xml").nil?
      header_footer.push("word/header#{i}.xml")
      i += 1
    end

    i = 1
    until zip.find_entry("word/footer#{i}.xml").nil?
      header_footer.push("word/footer#{i}.xml")
      i += 1
    end
  end
  header_footer
end

# Returns xmlText with hyperlinks and a list of References tags
def updateHyperlinks(xmlText)
  retHash = {}
  # Find urls
  urls = xmlText.scan(/<w:t>{{.*}}<\/w:t>/)
  # Resources for <Resources> tag
  retHash['urls'] = []
  retHash['id'] = []
  i = 25
  urls.each do |url|
    cleanUrl = url.gsub('{{', '').gsub('}}', '').tr(' ', '_')
    # set resourceId and xmlText
    resourceId = "r:id=\"rId#{i}\""
    xmlText = xmlText.gsub(url, "<w:hyperlink #{resourceId} w:history=\"1\"><w:r w:rsidRPr=\"00720130\"><w:rPr><w:rStyle w:val=\"Hyperlink\"/></w:rPr>#{cleanUrl}</w:r></w:hyperlink>")
    # remove tags
    cleanUrl = cleanUrl.gsub('<w:t>', '')
    cleanUrl = cleanUrl.gsub("<\/w:t>", '')
    # put urls in resources
    retHash['urls'].push(cleanUrl)
    retHash['id'].push("rId#{i}")
    i += 1
  end
  retHash['xmlText'] = xmlText
  retHash
end

def setHyperlinks(xmlText)
  urls = xmlText.scan(/<w:t>http(s).*<\/w:t>/)
  urls.each do |url|
    xmlText = xmlText.gsub(url, "<w:hyperlink><w:r><w:rPr><w:rStyle w:val=\"hyperLink\"/></w:rPr>#{url}</w:r></w:hyperlink>")
  end
  xmlText
end

def read_rels(zipfile, fil_r)
  content_types = ''

  Zip::File.open(zipfile) do |zipfile|
    content_types = zipfile.read(fil_r)
  end

  content_types
end

def write_rels(zipfile, fil_r, content)
  Zip::File.open(zipfile) do |zipfile|
    zipfile.get_output_stream(fil_r) { |f| f.write(content) }
  end
end

def zip_attachments(zip_file)
  Zip::Archive.open(zip_file, Zip::CREATE) do |zipfile|
    Dir['../attachments/*'].each do |name|
      zipfile.add_file(name)
    end
  end
end

# this tallies the findings by criticality and sets them as a udv
def add_findings_totals(udv, findings, config_options)
  critical = 0
  high = 0
  moderate = 0
  low = 0
  informational = 0

  udv ||= {}

  @cvssv2_scoring_override = if config_options.key?('cvssv2_scoring_override')
                               config_options['cvssv2_scoring_override']
                             else
                               false
                             end

  # Query for the findings that match the report_id
  if config_options['dread']
    findings.each do |finding|
      if finding.dread_total >= 40
        critical += 1
      elsif (finding.dread_total >= 30) && (finding.dread_total < 40)
        high += 1
      elsif (finding.dread_total >= 20) && (finding.dread_total <= 30)
        moderate += 1
      elsif (finding.dread_total >= 10) && (finding.dread_total <= 20)
        low += 1
      elsif (finding.dread_total >= 0) && (finding.dread_total <= 10)
        informational += 1
       end
    end
  elsif config_options['cvss']
    if @cvssv2_scoring_override
      findings.each do |finding|
        if finding.cvss_total >= 9
          critical += 1
        elsif finding.cvss_total >= 7
          high += 1
        elsif (finding.cvss_total >= 4) && (finding.cvss_total <= 6.9)
          moderate += 1
        elsif (finding.cvss_total >= 0.1) && (finding.cvss_total <= 3.9)
          low += 1
        elsif finding.cvss_total < 0.1
          informational += 1
        end
      end
    else
      findings.each do |finding|
        if finding.cvss_total >= 7
          high += 1
        elsif (finding.cvss_total >= 4) && (finding.cvss_total <= 6.9)
          moderate += 1
        elsif (finding.cvss_total >= 0) && (finding.cvss_total <= 3.9)
          low += 1
        end
      end
    end
  elsif config_options['cvssv3']
    findings.each do |finding|
      if finding.cvss_total >= 9
        critical += 1
      elsif (finding.cvss_total >= 7) && (finding.cvss_total <= 8.9)
        high += 1
      elsif (finding.cvss_total >= 4) && (finding.cvss_total <= 6.9)
        moderate += 1
      elsif (finding.cvss_total >= 0.1) && (finding.cvss_total <= 3.9)
        low += 1
      elsif finding.cvss_total < 0.1
        informational += 1
       end
    end
  elsif(config_options["nist800"])
    findings.each do |finding|
      if finding.nist800_total >= 240
        critical += 1
      elsif finding.nist800_total >= 150
        high += 1
      elsif finding.nist800_total >= 90
        moderate += 1
      elsif finding.nist800_total >= 50
        low += 1
      elsif finding.nist800_total <= 40
        informational += 1
      end
	  end
  else
    findings.each do |finding|
      if finding.risk == 4
        critical += 1
      elsif finding.risk == 3
        high += 1
      elsif finding.risk == 2
        moderate += 1
      elsif finding.risk == 1
        low += 1
      elsif finding.risk == 0
        informational += 1
      end
    end
  end

  udv['critical_tally'] = critical
  udv['high_tally'] = high
  udv['moderate_tally'] = moderate
  udv['low_tally'] = low
  udv['informational_tally'] = informational
  udv['total_tally'] = critical + high + moderate + low + informational

  udv
end

# The helper class exists to do string manipulation and heavy lifting
def url_escape_hash(hash)
  hash.each do |k, v|
    v ||= ''
    v = CGI.escapeHTML(v)

    if v
      # convert bullets
      v = v.gsub('*-', '<bullet>')
      v = v.gsub('-*', '</bullet>')

      # convert first nested bullets
      v = v.gsub('*=', '<bullet1>')
      v = v.gsub('=*', '</bullet1>')

      # convert h4
      v = v.gsub('[==', '<h4>')
      v = v.gsub('==]', '</h4>')

      # convert indent text
      v = v.gsub('[--', '<indented>')
      v = v.gsub('--]', '</indented>')

      # convert indent text
      v = v.gsub('[~~', '<italics>')
      v = v.gsub('~~]', '</italics>')
    end

    # replace linebreaks with paragraph xml elements
    if v =~ /\r\n/
      new_v = ''
      brs = v.split("\r\n")
      brs.each do |br|
        new_v << '<paragraph>'
        new_v << br
        new_v << '</paragraph>'
      end

      v = new_v
    elsif (k == 'remediation') || (k == 'overview') || (k == 'poc') || (k == 'affected_hosts') || (k == 'references')
      new_v = "<paragraph>#{v}</paragraph>"
      v = new_v
    end

    hash[k] = v
  end

  hash
end

def meta_markup(text)
  unless text.nil?
    new_text = text.gsub('<paragraph>', '&#x000A;').gsub('</paragraph>', '')
    new_text = new_text.gsub('<bullet>', '*-').gsub('</bullet>', '-*')
    new_text = new_text.gsub('<bullet1>', '*=').gsub('</bullet1>', '=*')
    new_text = new_text.gsub('<h4>', '[==').gsub('</h4>', '==]')
    new_text = new_text.gsub('<code>', '[[[').gsub('</code>', ']]]')
    new_text = new_text.gsub('<indented>', '[--').gsub('</indented>', '--]')
    new_text = new_text.gsub('<italics>', '[~~').gsub('</italics>', '~~]')
  end
end

# URL escaping messes up the inserted XML, this method switches it back to XML elements

def meta_markup_unencode(findings_xml, report)
  # code tags get added in later
  findings_xml = findings_xml.gsub('[[[', '<code>')
  findings_xml = findings_xml.gsub(']]]', '</code>')

  # creates paragraphs
  findings_xml = findings_xml.gsub('&lt;paragraph&gt;', '<paragraph>')
  findings_xml = findings_xml.gsub('&lt;/paragraph&gt;', '</paragraph>')
  # same for the bullets
  findings_xml = findings_xml.gsub('&lt;bullet&gt;', '<bullet>')
  findings_xml = findings_xml.gsub('&lt;/bullet&gt;', '</bullet>')
  findings_xml = findings_xml.gsub('&lt;bullet1&gt;', '<bullet1>')
  findings_xml = findings_xml.gsub('&lt;/bullet1&gt;', '</bullet1>')
  # same for the h4
  findings_xml = findings_xml.gsub('&lt;h4&gt;', '<h4>')
  findings_xml = findings_xml.gsub('&lt;/h4&gt;', '</h4>')
  # same for the code markings
  findings_xml = findings_xml.gsub('&lt;code&gt;', '<code>')
  findings_xml = findings_xml.gsub('&lt;/code&gt;', '</code>')
  # same for the indented text
  findings_xml = findings_xml.gsub('&lt;indented&gt;', '<indented>')
  findings_xml = findings_xml.gsub('&lt;/indented&gt;', '</indented>')
  # same for the indented text
  findings_xml = findings_xml.gsub('&lt;italics&gt;', '<italics>')
  findings_xml = findings_xml.gsub('&lt;/italics&gt;', '</italics>')

  # changes the <<any_var>> marks
  for i in report.instance_variables
    report_property = i[1..-1]
    findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;#{report_property}&amp;gt;&amp;gt;", report.instance_variable_get("@#{report_property}").to_s)
  end

  if report && report.user_defined_variables
    udv_hash = JSON.parse(report.user_defined_variables)
    udv_hash.each do |key, value|
      findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;#{key}&amp;gt;&amp;gt;", value.to_s)
    end
  end

  # this is for re-upping the comment fields
  findings_xml = findings_xml.gsub('&lt;modified&gt;', '<modified>')
  findings_xml = findings_xml.gsub('&lt;/modified&gt;', '</modified>')

  findings_xml = findings_xml.gsub('&lt;new_finding&gt;', '<new_finding>')
  findings_xml = findings_xml.gsub('&lt;/new_finding&gt;', '</new_finding>')

  # these are for beautification
  findings_xml = findings_xml.gsub('&amp;quot;', '"')
  findings_xml = findings_xml.gsub('&amp;', '&')
  findings_xml = findings_xml.gsub('&amp;lt;', '&lt;').gsub('&amp;gt;', '&gt;')

  findings_xml
end

# verify that the markup is sane
def mm_verify(hash)
  error = ''

  hash.each do |_k, text|
    text = CGI.escapeHTML(text)

    next unless text

    if text.include?('*-')
      elem = text.split('*-')
      elem.shift
      elem.each do |_bl|
        unless text.include?('-*')
          error = 'Markdown error, missing -* close tag.'
        end
      end
    end

    if text.include?('[==')
      elem = text.split('[==')
      elem.shift
      elem.each do |_bl|
        unless text.include?('==]')
          error = 'Markdown error, missing ==] close tag.'
        end
      end
    end

    if text.include?('[~~')
      elem = text.split('[~~')
      elem.shift
      elem.each do |_bl|
        unless text.include?('~~]')
          error = 'Markdown error, missing ~~] close tag.'
        end
      end
    end

    next unless text.include?('[[[')
    elem = text.split('[[[')
    elem.shift
    elem.each do |_bl|
      unless text.include?(']]]')
        error = 'Markdown error, missing ]]] close tag.'
      end
    end
  end
  error
end

def compare_text(new_text, orig_text)
  if orig_text.nil?
    # there is no master finding, must be new
    t = ''
    t << "<new_finding></new_finding>#{new_text}"
    return t
   end

  if new_text == orig_text
    return new_text
  else
    n_t = ''

    n_t << "<modified></modified>#{new_text}"
    return n_t
  end
end

# created NIST800 helper to cut down repetitive code
def nist800(data)
  if data["nist_impact"] == "Very Low"
    impact_val = 0
  elsif data["nist_impact"] == "Low"
    impact_val = 16
  elsif data["nist_impact"] == "Moderate"
    impact_val = 30
  elsif data["nist_impact"] == "High"
    impact_val = 40
  elsif data["nist_impact"] == "Very High"
    impact_val = 60
  end

  if data["nist_likelihood"] == "Very Low"
    likelihood_val = 1
  elsif data["nist_likelihood"] == "Low"
    likelihood_val = 2
  elsif data["nist_likelihood"] == "Moderate"
    likelihood_val = 3
  elsif data["nist_likelihood"] == "High"
    likelihood_val = 4
  elsif data["nist_likelihood"] == "Very High"
    likelihood_val = 5

  end

  nist800_total = impact_val * likelihood_val

  # Calulate nist total numeriacl score (Numbers used not NIST offical)
  # I came up with the math to match this table:
  # +------------+-----------+---------------+----------+----------+----------+-----------+
  # |                        |                       Impact                               |
  # +------------+-----------+---------------+----------+----------+----------+-----------+
  # |            |           |   Very Low    |   Low    | Moderate |   High   | Very High |
  # +            +-----------+---------------+----------+----------+----------+-----------+
  # |            | Very High |   Very Low    |   Low    | Moderate |   High   | Very High |
  # | likeihood  |   High    |   Very Low    |   Low    | Moderate |   High   | Very High |
  # |            | Moderate  |   Very Low    |   Low    | Moderate | Moderate |   High    |
  # |            |   Low     |   Very Low    |   Low    |   Low    |   Low    | Moderate  |
  # |            | Very Low  |   Very Low    | Very Low | Very Low |   Low    |   Low     |
  # +------------+-----------+---------------+----------+----------+----------+-----------+

  if nist800_total >= 240
    nist_rating = "Very High" 
  elsif nist800_total >= 150
    nist_rating = "High" 
  elsif nist800_total >= 90
    nist_rating = "Moderate" 
  elsif nist800_total >= 32
    nist_rating = "Low" 
  elsif nist800_total < 32
    nist_rating = "Very Low"
  end

  data['impact_val'] = impact_val
  data['likelihood_val'] = likelihood_val
  data['nist_rating'] = nist_rating
  data['nist800_total'] = nist800_total

  return data
end

# CVSS helper, there is a lot of hardcoded stuff
def cvss(data, is_cvssv3)
  # TODO: this needs to be refactored, cvss2 is calculated everytime
  unless is_cvssv3
    av = data['av'].downcase
    ac = data['ac'].downcase
    au = data['au'].downcase
    c = data['c'].downcase
    i = data['i'].downcase
    a = data['a'].downcase
    e = data['e'].downcase
    rl = data['rl'].downcase
    rc = data['rc'].downcase
    cdp = data['cdp'].downcase
    td = data['td'].downcase
    cr = data['cr'].downcase
    ir = data['ir'].downcase
    ar = data['ar'].downcase
  end

  # vector string
  c2_vs = 'CVSS:2.0/'

  # cvssV2
  if ac == 'high'
    cvss_ac = 0.35
    c2_vs += 'AC:H/'
  elsif ac == 'medium'
    cvss_ac = 0.61
    c2_vs += 'AC:M/'
  else
    cvss_ac = 0.71
    c2_vs += 'AC:L/'
  end

  if au == 'none'
    cvss_au = 0.704
    c2_vs += 'AU:N/'
  elsif au == 'single'
    cvss_au = 0.56
    c2_vs += 'AU:S/'
  else
    cvss_au = 0.45
    c2_vs += 'AU:M/'
  end

  if av == 'local'
    cvss_av = 0.395
    c2_vs += 'AV:L/'
  elsif av == 'adjacent network'
    cvss_av = 0.646
    c2_vs += 'AV:A/'
  else
    cvss_av = 1
    c2_vs += 'AV:N/'
  end

  if c == 'none'
    cvss_c = 0
    c2_vs += 'C:N/'
  elsif c == 'partial'
    cvss_c = 0.275
    c2_vs += 'C:P/'
  else
    cvss_c = 0.660
    c2_vs += 'C:C/'
  end
  if i == 'none'
    cvss_i = 0o0
    c2_vs += 'I:N/'
  elsif i == 'partial'
    cvss_i = 0.275
    c2_vs += 'I:P/'
  else
    cvss_i = 0.660
    c2_vs += 'I:C/'
  end

  if a == 'none'
    cvss_a = 0
    c2_vs += 'A:N/'
  elsif a == 'partial'
    cvss_a = 0.275
    c2_vs += 'I:P/'
  else
    cvss_a = 0.660
    c2_vs += 'I:C/'
  end

  # temporal score calculations
  if e == 'unproven exploit exists'
    cvss_e = 0.85
    c2_vs += 'E:U/'
  elsif e == 'proof-of-concept code'
    cvss_e = 0.90
    c2_vs += 'E:POC/'
  elsif e == 'functional exploit exists'
    cvss_e = 0.95
    c2_vs += 'E:F/'
  else
    cvss_e = 1
    c2_vs += 'E:H/'
  end

  if rl == 'official fix'
    cvss_rl = 0.87
    c2_vs += 'RL:OF/'
  elsif rl == 'temporary fix'
    cvss_rl = 0.90
    c2_vs += 'RL:TF/'
  elsif rl == 'workaround'
    cvss_rl = 0.95
    c2_vs += 'RL:W/'
  else
    cvss_rl = 1
    c2_vs += 'RL:U/'
  end

  if rc == 'unconfirmed'
    cvss_rc = 0.90
    c2_vs += 'RC:UC/'
  elsif rc == 'uncorroborated'
    cvss_rc = 0.95
    c2_vs += 'RC:UR/'
  else
    cvss_rc = 1
    c2_vs += 'RC:C/'
  end

  # environemental
  if cdp == 'low'
    cvss_cdp = 0.1
    c2_vs += 'CDP:L/'
  elsif cdp == 'low-medium'
    cvss_cdp = 0.3
    c2_vs += 'CDP:LM/'
  elsif cdp == 'medium-high'
    cvss_cdp = 0.4
    c2_vs += 'CDP:MH/'
  elsif cdp == 'high'
    cvss_cdp = 0.5
    c2_vs += 'CDP:H/'
  else
    cvss_cdp = 0
  end

  if td == 'none'
    c2_vs += 'TD:N/'
    cvss_td = 0
  elsif td == 'low'
    c2_vs += 'TD:L/'
    cvss_td = 0.25
  elsif td == 'medium'
    c2_vs += 'TD:M/'
    cvss_td = 0.75
  else
    c2_vs += 'TD:H/'
    cvss_td = 1
  end

  if cr == 'low'
    c2_vs += 'CR:L/'
    cvss_cr = 0.5
  elsif cr == 'high'
    c2_vs += 'CR:H/'
    cvss_cr = 1.51
  else
    c2_vs += 'CR:M/'
    cvss_cr = 1
  end

  if ir == 'low'
    cvss_ir = 0.5
    c2_vs += 'IR:L/'
  elsif ir == 'high'
    cvss_ir = 1.51
    c2_vs += 'IR:H/'
  else
    c2_vs += 'IR:M/'
    cvss_ir = 1
  end

  if ar == 'low'
    c2_vs += 'AR:L/'
    cvss_ar = 0.5
  elsif ar == 'high'
    c2_vs += 'AR:H/'
    cvss_ar = 1.51
  else
    c2_vs += 'AR:M/'
    cvss_ar = 1
  end

  cvss_impact = 10.41 * (1 - (1 - cvss_c) * (1 - cvss_i) * (1 - cvss_a))
  cvss_exploitability = 20 * cvss_ac * cvss_au * cvss_av
  cvss_impact_f = if cvss_impact == 0
                    0
                  else
                    1.176
                  end
  cvss_base = (0.6 * cvss_impact + 0.4 * cvss_exploitability - 1.5) * cvss_impact_f
  cvss_temporal = cvss_base * cvss_e * cvss_rl * cvss_rc
  cvss_modified_impact = [10, 10.41 * (1 - (1 - cvss_c * cvss_cr) * (1 - cvss_i * cvss_ir) * (1 - cvss_a * cvss_ar))].min
  cvss_modified_impact_f = if cvss_modified_impact == 0
                             0
                           else
                             1.176
                           end
  cvss_modified_base = (0.6 * cvss_modified_impact + 0.4 * cvss_exploitability - 1.5) * cvss_modified_impact_f
  cvss_adjusted_temporal = cvss_modified_base * cvss_e * cvss_rl * cvss_rc
  cvss_environmental = (cvss_adjusted_temporal + (10 - cvss_adjusted_temporal) * cvss_cdp) * cvss_td
  cvss_total = if cvss_environmental
                 cvss_environmental
               elsif cvss_temporal
                 cvss_temporal
               else
                 cvss_base
               end

  c3_vs = 'CVSS3.0:/'

  # cvssV3
  if is_cvssv3
    attack_vector = data['attack_vector'].downcase
    attack_complexity = data['attack_complexity'].downcase
    privileges_required = data['privileges_required'].downcase
    user_interaction = data['user_interaction'].downcase
    scope_cvss = data['scope_cvss'].downcase
    confidentiality = data['confidentiality'].downcase
    integrity = data['integrity'].downcase
    availability = data['availability'].downcase
    exploit_maturity = data['exploit_maturity'].downcase
    remeditation_level = data['remeditation_level'].downcase
    report_confidence = data['report_confidence'].downcase
    integrity_requirement = data['integrity_requirement'].downcase
    availability_requirement = data['availability_requirement'].downcase
    confidentiality_requirement = data['confidentiality_requirement'].downcase
    mod_attack_vector = data['mod_attack_vector'].downcase
    mod_attack_complexity = data['mod_attack_complexity'].downcase
    mod_privileges_required = data['mod_privileges_required'].downcase
    mod_user_interaction = data['mod_user_interaction'].downcase
    mod_scope = data['mod_scope'].downcase
    mod_confidentiality = data['mod_confidentiality'].downcase
    mod_integrity = data['mod_integrity'].downcase
    mod_availability = data['mod_availability'].downcase

    # Calculations taken from here:
    # https://gist.github.com/TheCjw/23b1f8b8f1da6ceb011c
    # https://www.first.org/cvss/specification-document#i8

    # Base
    if attack_vector == 'network'
      c3_vs += 'AV:N/'
      attack_vector_result = 0.85
    elsif attack_vector == 'adjacent'
      c3_vs += 'AV:A/'
      attack_vector_result = 0.62
    elsif attack_vector == 'local'
      c3_vs += 'AV:L/'
      attack_vector_result = 0.55
    elsif attack_vector == 'physical'
      c3_vs += 'AV:P/'
      attack_vector_result = 0.2
     end

    if attack_complexity == 'high'
      c3_vs += 'AC:H/'
      attack_complexity_result = 0.44
    elsif attack_complexity == 'low'
      c3_vs += 'AC:L/'
      attack_complexity_result = 0.77
      end

    if privileges_required == 'none'
      c3_vs += 'PR:N/'
      privileges_required_result = 0.85
    elsif privileges_required == 'high'
      c3_vs += 'PR:H/'
      if scope_cvss == 'changed' || mod_scope == 'changed'
        privileges_required_result = 0.50
      else
        privileges_required_result = 0.27
      end
    elsif privileges_required == 'low'
      c3_vs += 'PR:L/'
      if scope_cvss == 'changed' || mod_scope == 'changed'
        privileges_required_result = 0.68
      else
        privileges_required_result = 0.62
      end
      end

    if user_interaction == 'none'
      c3_vs += 'UI:N/'
      user_interaction_result = 0.85
    elsif user_interaction == 'required'
      c3_vs += 'UI:R/'
      user_interaction_result = 0.62
     end

    if scope_cvss == 'unchanged'
      c3_vs += 'S:U/'
      scope_cvss_result = 6.42
    else
      c3_vs += 'S:C/'
      scope_cvss_result = 7.52
     end

    if confidentiality == 'none'
      c3_vs += 'C:N/'
      confidentiality_result = 0.0
    elsif confidentiality == 'high'
      c3_vs += 'C:H/'
      confidentiality_result = 0.56
    elsif confidentiality == 'low'
      c3_vs += 'C:L/'
      confidentiality_result = 0.22
      end

    if integrity == 'none'
      c3_vs += 'I:N/'
      integrity_result = 0.0
    elsif integrity == 'high'
      c3_vs += 'I:H/'
      integrity_result = 0.56
    elsif integrity == 'low'
      c3_vs += 'I:L/'
      integrity_result = 0.22
     end

    if availability == 'none'
      c3_vs += 'A:N/'
      availability_result = 0.0
    elsif availability == 'high'
      c3_vs += 'A:H/'
      availability_result = 0.56
    elsif availability == 'low'
      c3_vs += 'A:L/'
      availability_result = 0.22
      end

    # Temporal
    if exploit_maturity == 'not defined'
      c3_vs += 'E:X/'
      exploit_maturity_result = 1
    elsif exploit_maturity == 'high'
      c3_vs += 'E:H/'
      exploit_maturity_result = 1
    elsif exploit_maturity == 'functional exploit exists'
      c3_vs += 'E:F/'
      exploit_maturity_result = 0.97
    elsif exploit_maturity == 'proof-of-concept code'
      c3_vs += 'E:P/'
      exploit_maturity_result = 0.94
    elsif exploit_maturity == 'unproven exploit exists'
      c3_vs += 'E:U/'
      exploit_maturity_result = 0.91
      end

    if remeditation_level == 'not defined'
      c3_vs += 'RL:X/'
      remeditation_level_result = 1
    elsif remeditation_level == 'unavailable'
      c3_vs += 'RL:U/'
      remeditation_level_result = 1
    elsif remeditation_level == 'workaround'
      c3_vs += 'RL:W/'
      remeditation_level_result = 0.97
    elsif remeditation_level == 'temporary fix'
      c3_vs += 'RL:T/'
      remeditation_level_result = 0.96
    elsif remeditation_level == 'official fix'
      c3_vs += 'RL:O/'
      remeditation_level_result = 0.95
      end

    if report_confidence == 'not defined'
      c3_vs += 'RC:X/'
      report_confidence_result = 1
    elsif report_confidence == 'confirmed'
      c3_vs += 'RC:C/'
      report_confidence_result = 1
    elsif report_confidence == 'reasonable'
      report_confidence_result = 0.96
      c3_vs += 'RC:R/'
    elsif report_confidence == 'unknown'
      report_confidence_result = 0.92
      c3_vs += 'RC:U/'
     end

    # Enviromental
    if confidentiality_requirement == 'not defined'
      c3_vs += 'CR:X/'
      confidentiality_requirement_result = 1
    elsif confidentiality_requirement == 'high'
      c3_vs += 'CR:H/'
      confidentiality_requirement_result = 1.5
    elsif confidentiality_requirement == 'medium'
      c3_vs += 'CR:M/'
      confidentiality_requirement_result = 1
    elsif confidentiality_requirement == 'low'
      c3_vs += 'CR:L/'
      confidentiality_requirement_result = 0.5
      end

    if integrity_requirement == 'not defined'
      c3_vs += 'IR:X/'
      integrity_requirement_result = 1
    elsif integrity_requirement == 'high'
      c3_vs += 'IR:H/'
      integrity_requirement_result = 1.5
    elsif integrity_requirement == 'medium'
      c3_vs += 'IR:M/'
      integrity_requirement_result = 1
    elsif integrity_requirement == 'low'
      c3_vs += 'IR:L/'
      integrity_requirement_result = 0.5
      end

    if availability_requirement == 'not defined'
      c3_vs += 'AR:X/'
      availability_requirement_result = 1
    elsif availability_requirement == 'high'
      c3_vs += 'AR:H/'
      availability_requirement_result = 1.5
    elsif availability_requirement == 'medium'
      c3_vs += 'AR:M/'
      availability_requirement_result = 1
    elsif availability_requirement == 'low'
      c3_vs += 'AR:L/'
      availability_requirement_result = 0.5
      end

    if mod_attack_vector == 'network'
      c3_vs += 'MAV:N/'
      mod_attack_vector_result = 0.85
    elsif mod_attack_vector == 'adjacent'
      c3_vs += 'MAV:A/'
      mod_attack_vector_result = 0.62
    elsif mod_attack_vector == 'local'
      c3_vs += 'MAV:L/'
      mod_attack_vector_result = 0.55
    elsif mod_attack_vector == 'physical'
      c3_vs += 'MAV:P/'
      mod_attack_vector_result = 0.2
    elsif mod_attack_vector == 'not defined'
      c3_vs += 'MAV:X/'
      mod_attack_vector_result = attack_vector_result
     end

    if mod_attack_complexity == 'high'
      c3_vs += 'MAC:H/'
      mod_attack_complexity_result = 0.44
    elsif mod_attack_complexity == 'low'
      c3_vs += 'MAC:L/'
      mod_attack_complexity_result = 0.77
    elsif mod_attack_complexity == 'not defined'
      c3_vs += 'MAC:X/'
      mod_attack_complexity_result = attack_complexity_result
      end

    if mod_privileges_required == 'none'
      c3_vs += 'MPR:N/'
      mod_privileges_required_result = 0.85
    elsif mod_privileges_required == 'low'
      c3_vs += 'MPR:L/'
      if scope_cvss == 'changed' || mod_scope == 'changed'
        mod_privileges_required_result = 0.68
      else
        mod_privileges_required_result = 0.62
      end
    elsif mod_privileges_required == 'high'
      c3_vs += 'MPR:H/'
      if scope_cvss == 'changed' || mod_scope == 'changed'
        mod_privileges_required_result = 0.5
      else
        mod_privileges_required_result = 0.27
      end
    elsif mod_privileges_required == 'not defined'
      c3_vs += 'MPR:X/'
      mod_privileges_required_result = privileges_required_result
      end

    if mod_user_interaction == 'none'
      c3_vs += 'MUI:N/'
      mod_user_interaction_result = 0.85
    elsif mod_user_interaction == 'required'
      c3_vs += 'MUI:R/'
      mod_user_interaction_result = 0.62
    elsif mod_user_interaction == 'not defined'
      c3_vs += 'MUI:X/'
      mod_user_interaction_result = user_interaction_result
      end

    if mod_scope == 'unchanged'
      c3_vs += 'MS:U/'
      mod_scope_result = 6.42
    elsif mod_scope == 'changed'
      c3_vs += 'MS:C/'
      mod_scope_result = 7.52
    elsif mod_scope == 'not defined'
      c3_vs += 'MS:X/'
      mod_scope_result = scope_cvss_result
     end

    if mod_confidentiality == 'none'
      c3_vs += 'MC:N/'
      mod_confidentiality_result = 0.0
    elsif mod_confidentiality == 'high'
      c3_vs += 'MC:H/'
      mod_confidentiality_result = 0.56
    elsif mod_confidentiality == 'low'
      c3_vs += 'MC:L/'
      mod_confidentiality_result = 0.22
    elsif mod_confidentiality == 'not defined'
      c3_vs += 'MC:X/'
      mod_confidentiality_result = confidentiality_result
     end

    if mod_integrity == 'none'
      c3_vs += 'MI:N/'
      mod_integrity_result = 0.0
    elsif mod_integrity == 'high'
      c3_vs += 'MI:H/'
      mod_integrity_result = 0.56
    elsif mod_integrity == 'low'
      c3_vs += 'MI:L/'
      mod_integrity_result = 0.22
    elsif mod_integrity == 'not defined'
      c3_vs += 'MI:X/'
      mod_integrity_result = integrity_result
      end

    if mod_availability == 'none'
      c3_vs += 'MA:N/'
      mod_availability_result = 0.0
    elsif mod_availability == 'high'
      c3_vs += 'MA:H/'
      mod_availability_result = 0.56
    elsif mod_availability == 'low'
      c3_vs += 'MA:L/'
      mod_availability_result = 0.22
    elsif mod_availability == 'not defined'
      c3_vs += 'MA:X/'
      mod_availability_result = availability_result
     end

    # Base Score
    cvss_exploitability = 8.22 * attack_vector_result * attack_complexity_result * privileges_required_result * user_interaction_result # exploitabilitySubScore
    cvss_impact_multipler = (1 - ((1 - confidentiality_result) * (1 - integrity_result) * (1 - availability_result))) # ISCbase

    if scope_cvss == 'unchanged'
      cvss_impact_score = scope_cvss_result * cvss_impact_multipler
    elsif scope_cvss == 'changed'
      cvss_impact_score = scope_cvss_result * (cvss_impact_multipler - 0.029) - 3.25 * ((cvss_impact_multipler - 0.02)**15)
      end

    cvss_base_score = 0 if cvss_impact_score <= 0

    if scope_cvss == 'unchanged'
      cvss_base_score = if (cvss_exploitability + cvss_impact_score) < 10
                          ((cvss_exploitability + cvss_impact_score) * 10).ceil / 10.0
                        else
                          10
                        end
    elsif scope_cvss == 'changed'
      if ((cvss_exploitability + cvss_impact_score) * 1.08) < 10
        cvss_base_score = (((cvss_exploitability + cvss_impact_score) * 1.08) * 10).ceil / 10.0
      else
        cvss_base_score = 10
      end
     end
    cvss_base_score = (cvss_base_score * 10).ceil / 10.0

    # Temporal Score
    cvss_temporal = (cvss_base_score * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil / 10.0

    # Enviromental Score
    cvss_mod_exploitability = 8.22 * mod_attack_vector_result * mod_attack_complexity_result * mod_privileges_required_result * mod_user_interaction_result

    if (1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)) > 0.915
      cvss_mod_impact_multipler = 0.915
    else
      cvss_mod_impact_multipler = 1 - (1 - mod_confidentiality_result * confidentiality_requirement_result) * (1 - mod_integrity_result * integrity_requirement_result) * (1 - mod_availability_result * availability_requirement_result)
      end

    if mod_scope == 'unchanged'
      cvss_mod_impact_score = mod_scope_result * cvss_mod_impact_multipler
    elsif mod_scope == 'changed'
      cvss_mod_impact_score = mod_scope_result * (cvss_mod_impact_multipler - 0.029) - 3.25 * ((cvss_mod_impact_multipler - 0.02)**15)
    elsif mod_scope == 'not defined'
      if scope_cvss == 'unchanged'
        cvss_mod_impact_score = scope_cvss_result * cvss_mod_impact_multipler
      elsif scope_cvss == 'changed'
        cvss_mod_impact_score = scope_cvss_result * (cvss_mod_impact_multipler - 0.029) - 3.25 * ((cvss_mod_impact_multipler - 0.02)**15)
      end
     end

    mod_impact_exploit_add = cvss_mod_impact_score + cvss_mod_exploitability

    if cvss_mod_impact_score <= 0
      cvss_environmental = 0
    else
      if mod_scope == 'not defined'
        if scope_cvss == 'unchanged'
          mod_impact_exploit_add = if mod_impact_exploit_add > 10
                                     10
                                   else
                                     (mod_impact_exploit_add * 10).ceil / 10.0
                                   end
          cvss_environmental = (mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil / 10.0
        elsif scope_cvss == 'changed'
          if ((1.08 * mod_impact_exploit_add * 10).ceil / 10.0) > 10
            mod_impact_exploit_add = 10
          else
            mod_impact_exploit_add = (1.08 * mod_impact_exploit_add * 10).ceil / 10.0
          end
          cvss_environmental = (mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil / 10.0
        end
       end
      if mod_scope == 'unchanged'
        mod_impact_exploit_add = if mod_impact_exploit_add > 10
                                   10
                                 else
                                   (mod_impact_exploit_add * 10).ceil / 10.0
                                 end
        cvss_environmental = (mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil / 10.0
      elsif mod_scope == 'changed'
        if ((1.08 * mod_impact_exploit_add * 10).ceil / 10.0) > 10
          mod_impact_exploit_add = 10
        else
          mod_impact_exploit_add = (1.08 * mod_impact_exploit_add * 10).ceil / 10.0
        end
        cvss_environmental = (mod_impact_exploit_add * exploit_maturity_result * remeditation_level_result * report_confidence_result * 10).ceil / 10.0
      end
      end
  end

  data['cvss_base'] = sprintf(format('%0.1f', cvss_base))
  data['cvss_impact'] = sprintf(format('%0.1f', cvss_impact))
  data['cvss_exploitability'] = sprintf(format('%0.1f', cvss_exploitability))
  data['cvss_temporal'] = sprintf(format('%0.1f', cvss_temporal))
  data['cvss_environmental'] = sprintf(format('%0.1f', cvss_environmental))
  data['cvss_modified_impact'] = sprintf(format('%0.1f', cvss_modified_impact))

  if is_cvssv3
    data['cvss_base_score'] = sprintf(format('%0.1f', cvss_base_score))
    data['cvss_impact_score'] = sprintf(format('%0.1f', cvss_impact_score))
    data['cvss_mod_impact_score'] = sprintf(format('%0.1f', cvss_mod_impact_score))

    data['cvss_total'] = sprintf(format('%0.1f', cvss_environmental))
  else
    data['cvss_total'] = sprintf(format('%0.1f', cvss_total))
  end

  data['c2_vs'] = c2_vs.chop
  data['c3_vs'] = c3_vs.chop

  data
end

# these are the scoring types; risk, dread and cvss, nist
#    this sets a score for all three in case the user switches later

def convert_score(finding)
  if finding.cvss_total.nil?
    puts '|!| No CVSS score exists'
    finding.cvss_total = 0
  end
  if finding.dread_total.nil?
    puts '|!| No DREAD score exists'
    finding.dread_total = 0
  end
  if finding.nist800_total.nil?
    puts '|!| No NIST800-30 score exists'
    finding.nist800_total = 0
  end
  if finding.risk.nil?
    puts '|!| No RISK score exists'
    finding.risk = 0
  end
  finding
end

# Get the type of scoring from the report and set the view variables, pull findings
def get_scoring_findings(report)
  if report.scoring.casecmp('dread').zero?
    findings = Findings.all(report_id: report.id, order: [:dread_total.desc])
    dread = true
    cvss = false
    cvss3 = false
    risk = false
    riskmatrix = false
    nist800 = false
  elsif report.scoring.casecmp('cvss').zero?
    findings = Findings.all(report_id: report.id, order: [:cvss_total.desc])
    dread = false
    cvss = true
    cvss3 = false
    risk = false
    riskmatrix = false
    nist800 = false
  elsif report.scoring.casecmp('cvssv3').zero?
    findings = Findings.all(report_id: report.id, order: [:cvss_total.desc])
    dread = false
    cvss = false
    cvss3 = true
    risk = false
    riskmatrix = false
    nist800 = false
  elsif report.scoring.casecmp('nist800').zero?
    findings = Findings.all(report_id: report.id, order: [:nist800_total.desc])
    dread = false
    cvss = false
    cvss3 = false
    risk = false
    riskmatrix = false
    nist800 = true
  elsif report.scoring.casecmp('riskmatrix').zero?
    findings = Findings.all(report_id: report.id, order: [:risk.desc])
    dread = false
    cvss = false
    cvss3 = false
    risk = false
    riskmatrix = true
    nist800 = false
  else
    findings = Findings.all(report_id: report.id, order: [:risk.desc])
    dread = false
    cvss = false
    cvss3 = false
    risk = true
    riskmatrix = false
    nist800 = false
  end

  [findings, dread, cvss, cvss3, risk, riskmatrix, nist800]
end

# Get the global configuration scoring algorithm and set at the report level
def set_scoring(config_options)
  if config_options['dread']
    return 'dread'
  elsif config_options['cvss']
    return 'cvss'
  elsif config_options['cvssv3']
    return 'cvssv3'
  elsif config_options['nist800']
    return 'nist800'
  elsif config_options['riskmatrix']
    return 'riskmatrix'
  end
  'risk'
end
