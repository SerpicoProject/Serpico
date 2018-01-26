# encoding: ASCII-8BIT
require 'rubygems'
require './model/master.rb'
require 'cgi'
require './helpers/helper'

# This does the heavy lifting for taking a report template and creating the resulting XSLT template.
#   It needs a lot of love but it works for now.

# This is a custom error class to be thrown if the template fails to parse correctly.
class ReportingError < RuntimeError
  attr_reader :errorString

  def initialize(errorString)
    @errorString = errorString
  end
end

def generate_excel_xslt(excel)
  xslts_components = {}

  # Initialize the xsl
  @top = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
  <xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes"/>
  <xsl:template match="/">
  <xsl:variable name="low" select="\'abcdefghijklmnopqrstuvwxyz\'" /><xsl:variable name="up" select="\'ABCDEFGHIJKLMNOPQRSTUVWXYZ\'" />
  <xsl:processing-instruction name="mso-application">
  <xsl:text>progid="Excel.Sheet"</xsl:text>
  </xsl:processing-instruction>'
  @bottom = '</xsl:template></xsl:stylesheet>'

  document = ''

  ###### SHAREDSTRINGS PART #############################################################

  # Excel saves all its user defined strings in a file called sharedstrings.xml
  # UDVs and serpico variables are substitued only for this file

  document = read_from_zip(excel, 'xl/sharedStrings.xml')
  # replace {} for the sake of XSL
  document = document.gsub('{', '{{').gsub('}', '}}')

  # metachar pairing verification
  worksheets = find_excel_worksheets(excel)
  shared_strings_noko = Nokogiri::XML(document)
  worksheets.each do |sheet|
    ws = read_from_zip(excel, sheet)
    # metacharacter_splitted_strings {} for the sake of XSL
    sheet_noko = Nokogiri::XML(ws)
    verify_paired_metacharacters(['æ', '∞', '§', 'π', 'Ω', '√'], sheet_noko, shared_strings_noko)
  end

  ###########################

  # Ω - used as a normal substituion variable

  # let's pull out variables
  metacharacter_splitted_strings = document.split('Ω')

  count = 0
  metacharacter_splitted_strings.each do |value_between_metachar|
    if count.even?
      count += 1
      next
    end

    # we metacharacter_splitted_strings ΩvalueΩ by the corresponding xsl code
    metacharacter_splitted_strings[count] = "<xsl:for-each select=\"report/reports\"><xsl:value-of select=\"#{value_between_metachar.downcase}\"/></xsl:for-each>"

    count += 1
  end

  # remove all the Ω and put the document back together
  document = metacharacter_splitted_strings.join('')

  ###########################

  # § - used as a user defined variable substituion variable

  # let's pull out variables
  metacharacter_splitted_strings = document.split('§')

  count = 0
  metacharacter_splitted_strings.each do |value_between_metachar|
    if count.even?
      count += 1
      next
    end

    # now, we metacharacter_splitted_strings metachar with the real deal
    # <xsl:for-each select="report/udv">
    # <xsl:value-of select="contact_name"/>
    # </xsl:for-each>
    metacharacter_splitted_strings[count] = "<xsl:for-each select=\"report/udv\"><xsl:value-of select=\"#{value_between_metachar.downcase}\"/></xsl:for-each>"
    count += 1
  end

  # remove all the § and put the document back together
  document = metacharacter_splitted_strings.join('')

  ###########################
  # √ - string comparison

  # For example, '√ short_company_name:::serpico testing √' is read as "compare short_company_name to 'serpico test' (case_insensitive) and return the result as true or false;  ..."

  metacharacter_splitted_strings = document.split('√')

  count = 0
  metacharacter_splitted_strings.each do |metachar|
    if count.even?
      count += 1
      next
    end

    left = metachar.split(':::').first.strip
    left = if left =~ /:/
             'report/udv/' + left.delete(':')
           elsif left =~ /\+/
             left.delete('+')
           else
             'report/reports/' + left
    end
    right = metachar.split(':::').last.strip

    metacharacter_splitted_strings[count] = "translate(#{left},$up,$low)=translate('#{right}',$up,$low)"

    count += 1
  end
  document = metacharacter_splitted_strings.join('')

  ###########################

  # π - a metacharacter_splitted_stringsment variable which takes full xpath

  metacharacter_splitted_strings = document.split('π')

  count = 0
  metacharacter_splitted_strings.each do |metachar|
    if count.even?
      count += 1
      next
    end

    metacharacter_splitted_strings[count] = "<xsl:value-of select=\"#{metachar.downcase}\"/>"
    count += 1
  end

  # remove all the π and put the document back together
  document = metacharacter_splitted_strings.join('')

  # we will need this during the worksheets xslt generation
  shared_strings_noko = Nokogiri::XML(document)

  ############################################################################################
  ###### WORKSHEETS PART

  worksheets = find_excel_worksheets(excel)
  worksheets.each do |sheet|
    document = read_from_zip(excel, sheet)
    # replace {} for the sake of XSL
    document = document.gsub('{', '{{').gsub('}', '}}')
    sheet_noko = Nokogiri::XML(document)
    verify_paired_metacharacters(['æ', '∞', '§', 'π', 'Ω', '√'], sheet_noko, shared_strings_noko)

    # æ - for each loop for table rows only
    # ::: - is used for if statements within the row
    # For example, 'æ findings:::X > 1 æ' is read as "for each finding with X greater than 1 create a new table row"


    # for every cell that has a shared string... (<v> contains the id of the shared string in excel)
    sheet_noko.xpath('//xmlns:worksheet/xmlns:sheetData/xmlns:row/xmlns:c[xmlns:v]').each do |c|
      # We get the shared string value of the current cell
      shared_string_value = get_shared_string_value(c, shared_strings_noko)
      if shared_string_value.include?('æ')

        xpath_between_ae_characters = shared_string_value.split('æ')[1]
        # we extract the iffies
        if shared_string_value.include?(':::')
          iffies_xpath = xpath_between_ae_characters.split(':::').drop(1)
          # we delete the remaining 'æ' in the condition
          iffies_xpath[-1] = iffies_xpath[-1].tr('æ', '')
          xpath_between_ae_characters = xpath_between_ae_characters.split(':::')[0]
        end
        # we find the row in which the æ were found
        parent_row = c.xpath('parent::xmlns:row')
        # we create the nested xslt conditions. This returns a nokogori node for the deepeest nested xslt condition
        # nested_iffies_xslt = create_nested_xslt_conditions(iffies_xpath, sheet_noko, parent = nil )
        # //xml:msub[count(descendant::xml:msub) = 0]
        # parent_row.children.first.add_previous_sibling(nested_iffies_xslt.at_xpath('ancestor::*[last()]'))
        # raise ReportingError, parent_row.to_xml

        # we add a for loop just above the row in which the æ were found
        parent_row.wrap("<xsl:for-each select=\"#{xpath_between_ae_characters}\"></xsl:for-each>")
        # we add the ::: conditions
        if iffies_xpath
          iffies_xpath.each do |xpath|
            parent_row.wrap("<xsl:if test=\"#{CGI.escapeHTML(xpath.downcase).gsub('&amp;', '&')}\"></xsl:if>")
          end
        end
        # now that the loop is ready, we replace each cells that contains the ∞ of the current row with the xpath between ∞
        cells_on_same_row_as_metacharacters = parent_row.xpath('xmlns:c[xmlns:v]')
        cells_on_same_row_as_metacharacters.each do |c_on_same_row|
          c_on_same_row_shared_string = get_shared_string_value(c_on_same_row, shared_strings_noko)
          # final_cell_value will be used to construct the final xslt string to inject in the cell
          final_cell_value_splitted = []
          # if there's at least one metacharacter pair
          if c_on_same_row_shared_string.include?('∞')
            splitted = c_on_same_row_shared_string.split('∞')
            final_cell_value = replace_value_between_metacharaters(splitted, '<xsl:value-of select="', '"/>')
            # now that we transformed the ∞ metacharacters in xslt,
            # we inject it in the cell were we found the "∞" metacharacters
            modify_shared_string_value(c_on_same_row, final_cell_value, shared_strings_noko)
            shared_string_to_inline_string(c_on_same_row, final_cell_value, sheet_noko)
          end
        end
      end
      ###################################################

      # † - if variable
      # For example, '† DREAD_SCORE > 1 †' is read as "if the DREAD_SCORE is greater than 1 then ..."

      if shared_string_value.include?('†')
        shared_string_value = get_shared_string_value(c, shared_strings_noko)

        values_between_if_characters = shared_string_value.split('†')
        final_cell_value = replace_value_between_metacharaters(values_between_if_characters, '<xsl:if test="', '">')
        modify_shared_string_value(c, final_cell_value, shared_strings_noko)
        # now that we transformed the † metacharacters in xslt,
        # we inject it in the cell were we found the "†" metacharacters
        shared_string_to_inline_string(c, final_cell_value, sheet_noko)
      end
      ############################################################
      # ¥ - ends an if statement

      next unless shared_string_value.include?('¥')
      shared_string_value = get_shared_string_value(c, shared_strings_noko)
      final_cell_value = shared_string_value.gsub('¥', '</xsl:if>')
      modify_shared_string_value(c, final_cell_value, shared_strings_noko)
      # now that we transformed the † metacharacters in xslt,
      # we inject it in the cell were we found the "¥" metacharacters
      shared_string_to_inline_string(c, final_cell_value, sheet_noko)
      #######################################################
    end

    # we clean the metacharacters in the sheet
    sheet_noko = clean_sheet('æ', sheet_noko)
    xslts_components[sheet] = @top + sheet_noko.to_xml + @bottom
  end
  #we clean the sharedstring so that they are not left in the final excel
  shared_strings_noko = clean_shared_strings('æ', shared_strings_noko)
  # because we cleaned the shared string, we need to update it in the returned xslts_components
  xslts_components['xl/sharedStrings.xml'] = @top + shared_strings_noko.to_xml + @bottom
  # return the xslts
  xslts_components
end

# returns the shared string value of a sheet cell
def get_shared_string_value(sheet_cell, shared_strings_noko)
  # ...We take the id of the shared string contained by the cell
  shared_string_id = sheet_cell.at_xpath('xmlns:v').content
  # ...we look in the shared strings file the corresponding value
  shared_string_value = shared_strings_noko.at_xpath("/xmlns:sst/xmlns:si[#{shared_string_id.to_i + 1}]/xmlns:t").content.to_s.force_encoding('ASCII-8BIT')
end

# modify the shared string value of a sheet cell
def modify_shared_string_value(sheet_cell, string, shared_strings_noko)
  # ...We take the id of the shared string contained by the cell
  shared_string_id = sheet_cell.at_xpath('xmlns:v').content
  # ...we look in the shared strings file the corresponding value
  shared_strings_noko.at_xpath("/xmlns:sst/xmlns:si[#{shared_string_id.to_i + 1}]/xmlns:t").content = string
  # raise ReportingError, shared_strings_noko.at_xpath("/xmlns:sst/xmlns:si[#{shared_string_id.to_i + 1}]/xmlns:t").content
end

# verify that the givin metacharacters are paired in the cells they are found in.
def verify_paired_metacharacters(metachars, sheet_noko, shared_strings_noko)
  metachars.each do |metachar|
    sheet_noko.xpath('//xmlns:worksheet/xmlns:sheetData/xmlns:row/xmlns:c[xmlns:v]').each do |sheet_cell|
      # ...We take the id of the shared string contained by the cell
      shared_string_value = get_shared_string_value(sheet_cell, shared_strings_noko)
      next unless shared_string_value.include?(metachar)
      # raise ReportingError, shared_string_value
      if shared_string_value.count(metachar).odd?
        rox_and_column_index = sheet_cell['r']
        raise ReportingError, "Uneven number of #{metachar} in cell #{rox_and_column_index}. This is usually caused by a mismatch in a variable."
      end
    end
  end
end

# transform a cell with a shared string value into a cell with an inline string value
# "string" var is used as the new value
# if the cell was already an inline string, it just adds the string to the already existing
# inline string
# inline string cells are like this :
#  <row r="1" spans="1:1">
#    <c r="A1" t="inlineStr">
#    <is><t>This is inline string example</t></is>
#    </c>
#  </row>
def shared_string_to_inline_string(c, string, sheet_noko)
  # we remove the v tag that is used as an index to the shared string
  # v_tag = c.at_xpath('xmlns:v')
  # v_tag.remove
  # we indicate that the cell value is an inline string
  if c['t'] != 'inlineStr'
    c['t'] = 'inlineStr'
    cell_descendants = c.xpath('descendant::*')
    # we create the needed tags and add the inline string value
    is_tag = Nokogiri::XML::Node.new 'is', sheet_noko
    t_tag = Nokogiri::XML.fragment("<t>#{string}</t>")
    # we add the created tags to the cell xml
    is_tag << t_tag
    c << is_tag
  else
    c.at_xpath('xmlns:is/xmlns:t').inner_html = string
    # raise ReportingError, string
  end
  c
end

# this function will delete the metacharacters from the shared strings
# For exemple "sdsdfdsf æsome_xpathæ" will become "sdsdffdsf".
# It returns the noko shared string document with the cleaned strings
def clean_shared_strings(metachar, shared_strings_noko)
  shared_strings_noko.xpath("//xmlns:t[contains(.,'#{metachar}')]").each do |shared_string|
    shared_string_value = shared_string.content.to_s.force_encoding('ASCII-8BIT')
    splitted = shared_string_value.split(metachar)
    count = 0
    cleaned_shared_string = []
    splitted.each do |_value_between_metachar|
      cleaned_shared_string << splitted[count] if count.even?
      count += 1
    end
    # raise ReportingError, cleaned_shared_string.join.inspect
    shared_string.content = cleaned_shared_string.join
  end
  shared_strings_noko
end

#clan the given sheet of the given metachar. Returns the cleaned sheet
def clean_sheet(metachar, sheet_noko)
  sheet_noko.xpath("//xmlns:t[contains(.,'#{metachar}')]").each do |inline_string|
    #inline_string_descendants = inline_string.xpath('descendant::*')
    inline_string_value = inline_string.inner_html.to_s.force_encoding('ASCII-8BIT')
    splitted = inline_string_value.split(metachar)
    count = 0
    cleaned_inline_string = []
    splitted.each do |_value_between_metachar|
      cleaned_inline_string << splitted[count] if count.even?
      count += 1
    end
    inline_string.inner_html = cleaned_inline_string.join
    #inline_string << inline_string_descendants
    #raise ReportingError, cleaned_inline_string.inspect
  end
  sheet_noko
end

# not used in the end, but could be useful. Recursivly create nested condition from an array of xpath used as conditions
def create_nested_xslt_conditions(iffies, sheet_noko, parent)
  if iffies.length == 1
    xslt_if_node = Nokogiri::XML::Node.new 'xsl:if', sheet_noko
    xslt_if_node['test'] = CGI.escapeHTML(iffies[0].downcase).gsub('&amp;', '&').to_s
    parent << xslt_if_node
    return xslt_if_node
  end
  xslt_if_node = Nokogiri::XML::Node.new 'xsl:if', sheet_noko
  xslt_if_node['test'] = CGI.escapeHTML(iffies[0].downcase).gsub('&amp;', '&').to_s
  parent << xslt_if_node unless parent.nil?
  next_iffies = iffies.drop(1)
  create_nested_xslt_conditions(next_iffies, sheet_noko, xslt_if_node)
end

def replace_value_between_metacharaters(splitted, xslt_beginning, xslt_ending)
  count = 0
  final_value_splitted = []
  splitted.each do |value_between_metachars|
    if count.odd?
      # we replace the value between metacharacters by the corresponding xsl code
      final_value_splitted.push("#{xslt_beginning}#{CGI.escapeHTML(value_between_metachars.downcase).gsub('&amp;', '&')}#{xslt_ending}")
    else
      final_value_splitted.push(value_between_metachars)
    end
    count += 1
  end
  final_value_splitted.join
end
