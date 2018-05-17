def parse_input(text)
  if text.nil? || (text == '<paragraph></paragraph>')
    return " None \n"
  else
    # replace paragragh
    text = text.gsub('<paragraph>', '').gsub('</paragraph>', "\n\n")

    # replace h4
    text = text.gsub('<h4>', '==== ').gsub('</h4>', '')

    # not sure asciidoc equivalent for indent
    text = text.gsub('<indented>', '').gsub('</indented>', '')

    # replace italics
    text = text.gsub('<italics>', '_').gsub('</italics>', '_')

    # replace bullet, doesn't take into account nesting
    text = text.gsub('<bullet>', "\n* ").gsub('</bullet>', '')

    # replace code
    text = text.gsub('<code>', '....').gsub('</code>', '....')
  end
  text
end

# takes in a serpico finding and returns asciidoc version
def gen_asciidoc(finding, score)
  asciidoc = ''

  asciidoc << "== #{finding.title} \n\n"

  if score == 'dread'
    asciidoc << "|====== \n"
    asciidoc << "|Damage|Reproducibility|Exploitability|Affected Users|Discoverability|Remediation Effort\n"
    asciidoc << "|#{finding.damage} \n"
    asciidoc << "|#{finding.reproducability} \n"
    asciidoc << "|#{finding.exploitability} \n"
    asciidoc << "|#{finding.affected_users} \n"
    asciidoc << "|#{finding.discoverability} \n"
    asciidoc << "|#{finding.effort} \n"
    asciidoc << "|======\n\n"
  elsif (score == 'cvss') || (score == 'cvssv3')
    asciidoc << "|====== \n"
    asciidoc << '|CVSS Score Total:'
    asciidoc << "|#{finding.cvss_total} \n"
    asciidoc << "|======\n\n"
  else
    risk = %w[Informational Low Moderate High Critical]
    asciidoc << "|===\n"
    asciidoc << "|Risk |Remediation Effort\n"
    asciidoc << "|#{risk[finding.risk]} \n"
    asciidoc << "|#{finding.effort} \n"
    asciidoc << "|===\n\n"
  end

  asciidoc << "=== Overview \n"
  asciidoc << parse_input(finding.overview) + "\n"
  asciidoc << "=== Affected Hosts \n"
  asciidoc << parse_input(finding.affected_hosts) + "\n"
  asciidoc << "=== Proof of Concept \n"
  asciidoc << parse_input(finding.poc) + "\n"
  asciidoc << "=== Remediation \n"
  asciidoc << parse_input(finding.remediation) + "\n"
  asciidoc << "=== References \n"
  asciidoc << parse_input(finding.references) + "\n\n"
  asciidoc << "<<< \n\n"
  asciidoc
end
