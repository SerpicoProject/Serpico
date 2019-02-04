require 'rubygems'
require './model/master.rb'
require 'cgi'
require './helpers/helper'


# This does the heavy lifting for taking a report template and creating the resulting XSLT template.
#   It needs a lot of love but it works for now.

# This is a custom error class to be thrown if the template fails to parse correctly.
class ReportingError < RuntimeError
  attr :errorString

  def initialize(errorString)
    @errorString = errorString
  end
end

class TemplateVerificationError < ReportingError
	attr :template_tree

	def initialize(errorString, template_tree)
	  super(errorString)
	  @template_tree = template_tree
	end

	def to_s
	  return "#{errorString}"
	end
end

def locate_error(error, document, position)
	text_before = document[0..position].scan(/<w:t>.*?<\/w:t>/)
	text_after = document[position..-1].scan(/<w:t>.*?<\/w:t>/)

	error.concat(" between : \n")
	nb_text = [text_before.count, 10].min

	while nb_text != 0
		# remove the tags before concatenate text
		message = text_before[-1*nb_text][5..-7]
		error.concat("#{message}, ")
		nb_text = nb_text - 1
	end
	error.concat("\nand \n")
	nb_text = [text_after.count, 10].min
	k = 0
	while nb_text != k
		message = text_after[k][5..-7]
		error.concat("#{message}, ")
		k = k + 1
	end
	return error
end

def verify_document(document)
	metacharacters = document.enum_for(:scan,/Ω|§|¬|π|æ|∞|†|µ|ƒ|÷|å|≠|∆|¥|ツ|⁂|<\/w:tr>/).map { |b| [Regexp.last_match.begin(0),b] }
	i=0
	buffer = []
	tree = ""
	error = ""
	tree_valid = true
	while i<metacharacters.length
	  case metacharacters[i][1]
		# ¬ character
		when "¬"
		  tabs = "\t" * buffer.length
		  if metacharacters[i+1][1] != "¬"
			tree_valid = false
			error = "Error with a ¬ character : character without pair"
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}¬  ←\n")
			break
		  end
		  condition = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  if i+2 < metacharacters.length && metacharacters[i+2][1] == "µ"
			tree.concat("#{tabs}¬#{condition}¬ ")
		  else
			tree.concat("#{tabs}¬#{condition}¬\n")
		  end
		  buffer.push("¬")
		  i = i+1


		# ∆ character
		when "∆"
		  previous = buffer.pop()
		  tabs = "\t" * buffer.length
		  if previous != "¬"
			if previous == "†"
			  error = "error when closing condition, expected ¥, got ∆ instead"
			elsif previous =~ /¬µ/
			  error = "error when closing choose structure, expected ≠, got ∆ instead"
			elsif previous =~ /µ/
			  error = "error when closing choose structure, expected å, got ∆ instead"
			else
			  error = "error when closing structure, unexpected ∆"
			end
			locate_error(error, document, metacharacters[i][0])
			tree_valid = false

			tree.concat("#{tabs}∆  ←\n")
			break
		  end
		  tree.concat("#{tabs}∆\n")


		# † character
		when "†"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != '†')
			tree_valid = false
			error = "Error with a † character : character without pair"
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}†  ←\n")
			break
		  end
		  condition = document[metacharacters[i][0]+3..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}†#{condition}†\n")
		  buffer.push("†")
		  i = i+1

		# ¥ character
		when "¥"
		  previous = buffer.pop()
		  tabs = "\t" * buffer.length

		  if previous != "†"
			if previous == "¬"
			  error = "error when closing loop, expected ∆, got ¥ instead"
			elsif previous =~ /^¬µ/
			  error = "error when closing choose structure, expected ≠, got ¥ instead"
			elsif previous =~ /^µ/
			  error = "error when closing choose structure, expected å, got ¥ instead"
			else
			  error = "error when closing structure, unexpected ¥"
			end
			# error.concat" at line #{document[0..metacharacters[i][0]].scan(/(?=<w:p( |>))/).count}"
			locate_error(error, document, metacharacters[i][0])
			tree_valid = false

			tree.concat("#{tabs}¥  ←\n")
			break
		  end
		  tree.concat("#{tabs}¥\n")



		# µ character
		when "µ"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != 'µ')
			error = "Error with a µ character : character without pair"
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}µ  ←\n")
			break
		  end
		  condition = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  if buffer[-1] == "¬"
			tree.concat("µ#{condition}µ\n")
			buffer[-1] = "¬µ"
		  else
			tree.concat("#{tabs}µ#{condition}µ\n")
			buffer.push("µ")
		  end
		  i = i+1


		# ƒ character
		when "ƒ"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != 'ƒ')
			error = "Error with a ƒ character : character without pair"
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}ƒ  ←\n")
			break
		  end
		  condition = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  if buffer[-1] == "µ" || buffer[-1] == "¬µ"
			tree.concat("#{tabs}ƒ#{condition}ƒ\n")
		  elsif buffer[-1] == "¬µ÷" || buffer[-1] == "µ÷"
			error = "Error with a ƒ character : character must be before the ÷ character"
			tree_valid = false
			tree.concat("#{tabs}ƒ#{condition}ƒ  ←\n")
			break
		  else
			error = "Error with a ƒ character : character must be inside a choose structure"
			tree_valid = false
			tree.concat("#{tabs}ƒ#{condition}ƒ  ←\n")
			break
		  end
		  i = i+1

		# ÷ character
		when "÷"
		  tabs = "\t" * buffer.length
		  if buffer[-1] == "µ" || buffer[-1] == "¬µ"
			tree.concat("#{tabs}÷\n")
			buffer[-1] = buffer[-1] + "÷"
		  else
			error = "Error with a ÷ character : character must be inside a choose structure"
			tree.concat("#{tabs}÷  ←\n")
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])
			break
		  end

		# ≠ character
		when "≠"
		  previous = buffer.pop()
		  tabs = "\t" * buffer.length

		  if previous != "¬µ÷"
			if previous == "¬"
			  error = "error when closing loop, expected ∆, got ≠ instead"
			elsif previous =~ /^µ/
			  error = "error when closing choose structure, expected å, got ≠ instead"
			elsif previous == "†"
			  error = "error when closing condition, expected ¥, got ≠ instead"
			elsif previous == "¬µ"
			  error = "error when closing choose structure, missing ÷ before ≠"
			else
			  error = "error when closing structure, unexpected ≠"
			end
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])

			tree.concat("#{tabs}≠  ←\n")
			break
		  end
		  tree.concat("#{tabs}≠\n")

		# å character
		when "å"
		  previous = buffer.pop()
		  tabs = "\t" * buffer.length

		  if previous != "µ÷"
			if previous == "¬"
			  error = "error when closing loop, expected ∆, got å instead"
			elsif previous =~ /¬µ/
			  error = "error when closing choose structure, expected ≠, got å instead"
			elsif previous == "†"
			  error = "error when closing condition, expected ¥, got å instead"
			elsif previous == "µ"
			  error = "error when closing choose structure, missing ÷ before å"
			else
			  error = "error when closing structure, unexpected å"
			end
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])

			tree.concat("#{tabs}å  ←\n")
			break
		  end
		  tree.concat("#{tabs}å\n")
		# ツ character
		when "ツ"
		  # check if there is anything else than π between two ツ
		  j = 1
		  while j+i < metacharacters.length
			if metacharacters[j+i][1] == "ツ"
			  break
			elsif metacharacters[j+i][1] != "π"
			  tree_valid = false
			  break
			end
			j = j+1
		  end

		  tabs = "\t" * buffer.length

		  if j+i == metacharacters.length || not(tree_valid)
			error = "Error with a ツ character : character without pair"
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}ツ  ←\n")
			break
		  end

		  if j.even?
			error = "Error with a π character : character without pair"
			tree_valid = false
			content = document[metacharacters[i][0]+3..metacharacters[i+j][0]-1].gsub(/<.*?>/,"")
			tree.concat("#{tabs}ツ#{content}ツ  ←\n")
			break
		  end


		  content = document[metacharacters[i][0]+3..metacharacters[i+j][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}ツ#{content}ツ\n")
		  i = i+j



		# § character
		when "§"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != '§')
			error = "Error with a § character : character without pair"
			locate_error(error, document, metacharacters[i][0])
			tree.concat("#{tabs}§  ←\n")
			tree_valid = false
			break
		  end
		  content = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}§#{content}§\n")
		  i = i+1


		# Ω character
		when "Ω"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != 'Ω')
			error = "Error with a Ω character : character without pair"
			tree.concat("#{tabs}Ω  ←\n")
			tree_valid = false
			locate_error(error, document, metacharacters[i][0])
			break
		  end
		  content = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}Ω#{content}Ω\n")
		  i = i+1
		# π character
		when "π"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != 'π')
			error = "Error with a π character : character without pair"
			tree_valid = false
			tree.concat("#{tabs}π  ←\n")
			locate_error(error, document, metacharacters[i][0])
			break
		  end

		  content = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}π#{content}π\n")
		  i = i+1

		# æ character
		when "æ"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != 'æ')
			error = "Error with a æ character : character without pair"
			tree_valid = false
			tree.concat("#{tabs}æ  ←\n")
			locate_error(error, document, metacharacters[i][0])
			break
		  end

		  condition = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")

		  if /<w:tbl[ >]((?<!<\/w:tbl>).)*$/.match(document[0..metacharacters[i][0]]).nil?
			error = "Error with a æ character : character must be inside of table"
			tree_valid = false
			tree.concat("#{tabs}æ#{condition}æ  ←\n")
			locate_error(error, document, metacharacters[i][0])
			break
		  end
		  tree.concat("#{tabs}æ#{condition}æ\n")
		  buffer.push("æ")
		  i = i+1

		# ∞ character
		when "∞"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || metacharacters[i + 1][1] != '∞'
			error = "Error with a ∞ character : character without pair"
			tree_valid = false
			tree.concat("#{tabs}∞  ←\n")
			locate_error(error, document, metacharacters[i][0])
			break
		  end

		  condition = document[metacharacters[i][0]+3..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")

		  tree.concat("#{tabs}∞#{condition}∞\n")
		  i = i+1


		# ⁂ character
    # =>  XSLT Code Blocks
		when "⁂"
		  tabs = "\t" * buffer.length
      if (i == metacharacters.length - 1) || (metacharacters[i + 1][1] != '⁂')
			error = "Error with a ⁂ character : character without pair"
			tree_valid = false
			tree.concat("#{tabs}⁂  ←\n")
			locate_error(error, document, metacharacters[i][0])
			break
		  end

		  content = document[metacharacters[i][0]+2..metacharacters[i+1][0]-1].gsub(/<.*?>/,"")
		  tree.concat("#{tabs}⁂#{content}⁂\n")
		  i = i+1



		# end of table
		when "<\/w:tr>"
		  if buffer[-1] == "æ"
			buffer.pop()
		  end

	  end

	  i = i+1
	end
	if not(buffer.empty?) && tree_valid
	  previous = buffer.pop()
	  tabs = "\t" * buffer.length
	  if previous == "†"
		error = "error :  condition not closed, expected ¥"
	  elsif previous == /^µ/
		error = "error : choose structure nor closed, expected å"
	  elsif previous == /¬µ/
		error = "error : choose structure not closed, expected ≠"
	  elsif previous == "¬"
		error = "error : loop not closed, expected ∆"
	  else
		error = "error : structure not closed"
	  end
	  # locate_error(error, document, document[-1])
	  tree.concat("#{tabs}←\n")
	  tree_valid = false
	end

	return tree_valid, error, tree

end

def generate_xslt(docx)

# Initialize the xsl
@top = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xsl:stylesheet
version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" indent="yes"/>
<xsl:template match="/">
<xsl:variable name="low" select="\'abcdefghijklmnopqrstuvwxyz\'" /><xsl:variable name="up" select="\'ABCDEFGHIJKLMNOPQRSTUVWXYZ\'" />
<xsl:processing-instruction name="mso-application">
<xsl:text>progid="Word.Document"</xsl:text>
</xsl:processing-instruction>'
@bottom = '</xsl:template></xsl:stylesheet>'

	document = ""
	debug = false

	document = read_rels(docx,"word/document.xml")
  document.force_encoding('UTF-8')

	tree_valid, error, tree = verify_document(document)
	if not(tree_valid)
	  raise TemplateVerificationError.new(error,tree)
	end

	# fix for curly apostrophes
	document = document.gsub(/‘/,"'")
	document = document.gsub(/’/,"'")
	document = document.gsub(/“/,"\"")
	document = document.gsub(/”/,"\"")

	#add line breaks for easier reading, only use with debugging
	#document = document.gsub('>',">\n")

	# replace {} for the sake of XSL
	document = document.gsub("{","{{").gsub("}","}}")

	# add in xslt header
	document = @top + document

	for_iffies = []



###########################

# Ω - used as a normal substituion variable

# let's pull out variables
	replace = document.split('Ω')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of Ω. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		# now, we replace omega with the real deal
		#<xsl:for-each select="report/reports">
		#<w:t xml:space="preserve"> <xsl:value-of select="contact_name"/> </w:t>
		#</xsl:for-each>
		replace[count] = "<xsl:for-each select=\"report/reports\"><xsl:value-of select=\"#{omega.downcase}\"/></xsl:for-each>"
		count = count + 1
	end

	# remove all the Ω and put the document back together
	document = replace.join("")

###########################

# § - used as a user defined variable substituion variable

# let's pull out variables
    replace = document.split('§')

    if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of §. This is usually caused by a mismatch in a variable.")
    end

    count = 0
    replace.each do |omega|
        if (count % 2) == 0
            count = count + 1
            next
        end

        omega = compress(omega)

        # now, we replace omega with the real deal
        #<xsl:for-each select="report/reports">
        #<w:t xml:space="preserve"> <xsl:value-of select="contact_name"/> </w:t>
        #</xsl:for-each>
        replace[count] = "<xsl:for-each select=\"report/udv\"><xsl:value-of select=\"#{omega.downcase}\"/></xsl:for-each>"
        count = count + 1
    end

    # remove all the Ω and put the document back together
    document = replace.join("")


###########################

# π - a replacement variable for for-each loops only

	replace = document.split('π')

	if (((replace.size-1) % 2) != 0)
	    raise ReportingError.new("Uneven number of π. This is usually caused by a mismatch in a variable.")
    end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		replace[count] = "<xsl:value-of select=\"#{omega.downcase}\"/>"
		count = count + 1
	end

	document = replace.join("")
###########################

# ∞ - a replacement variable for for-each loops inside tables only

	#let us replace the xsl when test
	replace = document.split('∞')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of ∞. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		replace[count] = "<xsl:value-of select=\"#{omega.downcase}\"/>"

		count = count + 1
	end

	document = replace.join("")



###############################

# √ - string comparison

# For example, '√ short_company_name:::serpico testing √' is read as "compare short_company_name to 'serpico test' (case_insensitive) and return the result as true or false;  ..."

	replace = document.split('√')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of √. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		left = omega.split(":::").first.strip
		if left =~ /:/
			left = "report/udv/"+left.gsub(":","")
		elsif left =~ /\+/
			left = left.gsub("+","")
		else
			left = "report/reports/"+left
		end
		right = omega.split(":::").last.strip

		replace[count]="translate(#{left},$up,$low)=translate('#{right}',$up,$low)"

		count = count + 1

	end
	document = replace.join("")


###########################

# æ - for each loop for table rows only
# ::: - is used for if statements within the row

# For example, 'æ findings:::X > 1 æ' is read as "for each finding with X greater than 1 create a new table row"

	replace = document.split('æ')

	if (((replace.size-1) % 2) != 0)
	    raise ReportingError.new("Uneven number of æ. This is usually caused by a mismatch in a variable.")
    end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		if omega =~ /:::/
			conditions = omega.split(":::")
			ifies = conditions.size - 1
			omega = conditions[0]

			#skip back to the previous TABLEROW <w:tr
			if replace[count-1] =~ /\<w:tr /
				conditions.shift
				q = ""

				conditions.each do |condition|
					# add uppercase/lowercase to allow users to test for string matches (e.g. type='Database')
					q << "<xsl:if test=\"#{CGI.escapeHTML(condition.downcase).gsub("&amp;","&")}\">"
				end
				q << "<w:tr "
				x = replace[count-1].reverse.sub("<w:tr ".reverse,"<xsl:for-each select=\"#{omega.downcase}\">#{q}".reverse).reverse
				replace[count-1] = x
			end


			#skip back to the previous TABLEROW <w:tr
			if replace[count+1] =~ /\<\/w:tr/
				ends = "</xsl:if>"*ifies
				z = replace[count+1].sub('</w:tr>',"</w:tr>#{ends}</xsl:for-each>")
				replace[count+1] = z
			end

			replace[count]=''

		else
			#skip back to the previous TABLEROW <w:tr
			if replace[count-1] =~ /\<w:tr /
				x = replace[count-1].reverse.sub("<w:tr ".reverse,"<xsl:for-each select=\"#{omega.downcase}\"><w:tr ".reverse).reverse
				replace[count-1] = x
			end

			replace[count]=''

			#skip back to the previous TABLEROW <w:tr
			if replace[count+1] =~ /\<\/w:tr/
				z = replace[count+1].sub('</w:tr>','</w:tr></xsl:for-each>')
				replace[count+1] = z
			end
		end

		count = count + 1
	end

	document = replace.join("")

###########################

# ¬ - for each
# ::: - if statement within the for each

# For example, '¬ finding:::DREAD_SCORE > 1 ¬' is read as "for each finding with a DREAD score greater than 1"

	replace = document.split('¬')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of ¬. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		q = ""
		if omega =~ /:::/
			conditions = omega.split(":::")
			for_iffies.push(conditions.size-1)
			omega = conditions[0]

			conditions.shift
			conditions.each do |condition|
				# add uppercase/lowercase to allow users to test for string matches (e.g. type='Database')
				q << "<xsl:if test=\"#{CGI.escapeHTML(condition.downcase).gsub("&amp;","&")}\">"
			end
        else
			for_iffies.push(0)
		end

		# we need to search backwards for '<w:p>' or '<w:p ')
		woutspace = replace[count-1].rindex("<w:p>")
		space = replace[count-1].rindex("<w:p ")
		woutspace = 0 unless woutspace
		space = 0 unless space

		if woutspace > space
			x = replace[count-1].reverse.sub("<w:p>".reverse,"<xsl:for-each select=\"#{omega.downcase}\">#{q}<w:p>".reverse).reverse
			replace[count-1] = x
		else
			x = replace[count-1].reverse.sub("<w:p ".reverse,"<xsl:for-each select=\"#{omega.downcase}\">#{q}<w:p ".reverse).reverse
			replace[count-1] = x
		end
		replace[count]=''

		count = count + 1
	end

	document = replace.join("")

###############################

# † - if variable

# For example, '† DREAD_SCORE > 1 †' is read as "if the DREAD_SCORE is greater than 1 then ..."

	replace = document.split('†')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of †. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		x = replace[count-1].reverse.sub("</w:p>".reverse,"</w:p><xsl:if test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\">".reverse).reverse
		replace[count-1] = x

		replace[count]=''

		count = count + 1
	end
	document = replace.join("")


###########################
# ÷ - otherwise . Used in XSLT choose loops
  otherwise_results = ""
  document.each_line('÷') { |line|
    paragraph_style = ""
    paragraph_style_index = line.reverse.index("<w:pPr>".reverse)
    paragraph_index = line.reverse.index(/[ >]p:w</)

    if paragraph_style_index and paragraph_index
      if paragraph_style_index < paragraph_index
        paragraph_style_index = paragraph_style_index + "<w:pPr>".length
        paragraph_style_end_index = line.reverse.index("</w:pPr>".reverse)
        paragraph_style = line.reverse[paragraph_style_end_index, (paragraph_style_index - paragraph_style_end_index)].reverse
      end
    end

    otherwise_results << line.gsub('÷',"</w:t></w:r></w:p></xsl:when><xsl:otherwise><w:p>" + paragraph_style + "<w:r><w:t>")
  }
	document = otherwise_results

###########################
# ¥ - ends an if statement

	q = ""
	subst = false
	document.each_line("¥"){ |a|
		if subst
			x = ""
			# we need to search forwards for '</w:p>'
			x = a.sub("</w:t></w:r></w:p>","</xsl:if>")
			a = x
			subst = false
		end

		if a =~ /¥/
			#remove the start of the paragraph
			alength = a.length
			woutspace = a.rindex("<w:p>")
			space = a.rindex("<w:p ")
			woutspace = 0 unless woutspace
			space = 0 unless space

			if woutspace > space
				a.slice!(woutspace..alength)
			else
				a.slice!(space..alength)
			end
			subst = true
		end

		q << a.gsub('¥','')
	}
	document = q

###########################

# ƒ - the when value in a choose statement

# For example, 'ƒcodeƒ OUTPUT' is read as "when the current type is code, write 'OUTPUT'"; see XSLT choose/when/otherwise

	replace = document.split('ƒ')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of ƒ. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		# we need to search backwards for '<w:p>' or '<w:p ')
		woutspace = replace[count-1].rindex("<w:p>")
		space = replace[count-1].rindex("<w:p ")
		woutspace = 0 unless woutspace
		space = 0 unless space
		x = ""
		if woutspace > space
			x = replace[count-1].reverse.sub("</w:p>".reverse,"</w:p></xsl:when><xsl:when test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\">".reverse).reverse
			replace[count-1] = x
		else
			x = replace[count-1].reverse.sub("</w:p>".reverse,"</w:p></xsl:when><xsl:when test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\">".reverse).reverse
			replace[count-1] = x
		end
		replace[count]=''

		count = count + 1
	end

	document = replace.join("")
###############################

# µ - initiates choose/when structure

	replace = document.split('µ')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of µ. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		omega = compress(omega)

		# we need to search backwards for '<w:p>' or '<w:p ')
		woutspace = replace[count-1].rindex("<w:p>")
		space = replace[count-1].rindex("<w:p ")
		woutspace = 0 unless woutspace
		space = 0 unless space
		x = ""
		if woutspace > space
			x = replace[count-1].reverse.sub("<w:p>".reverse,"<xsl:choose><xsl:when test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\"><w:p>".reverse).reverse
			replace[count-1] = x
		else
			x = replace[count-1].reverse.sub("<w:p ".reverse,"<xsl:choose><xsl:when test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\"><w:p ".reverse).reverse
			replace[count-1] = x
		end
		replace[count]=''

		count = count + 1
	end

	document = replace.join("")

###############################

###########################
# å - the end of choose structure

	q = ""
	subst = false
	document.each_line("å"){ |a|
		if subst
			x = ""
			# we need to search forwards for '</w:p>'
			x = a.sub("</w:p>","</w:p></xsl:otherwise></xsl:choose>")
			a = x
			subst = false
		end

		if a =~ /å/
			subst = true
		end

		q << a.gsub('å','')
	}
	document = q

	#######
	# This is ugly but we have to presort the for_iffies and assign them
	#	to the proper loop. This is because there are two types of
	#	closing elements in a for loop, ∆ and ≠. In the case of ≠, you
	#	can't use an if element so we shouldn't close for it.

	r_for_iffies = []
	count = 0

	document.split(" ").each do |current|
		if current =~ /∆/ or current =~ /≠/
			if current =~ /∆/
				# pull out the first count of elements
				sub_iffies = for_iffies[0..count]

				elem = sub_iffies[0]
				r_for_iffies.push(elem)

				0.upto(count) do |n|
					for_iffies.shift
				end
				count = -1
			end
			count = count + 1
		end
	end


###########################

# ≠ - end of choose structure inside of a for-each loop

	q = ""
	subst = false
	document.each_line("≠"){ |a|
		if subst
			x = ""
			# we need to search forwards for '</w:p>'
			x = a.sub("</w:p>","</w:p></xsl:otherwise></xsl:choose></xsl:for-each>")
			a = x
			subst = false
		end

		if a =~ /≠/
			subst = true
		end

		q << a.gsub('≠','')
	}
	document = q


###############################
# ∆ - end for-each

    # add end if's
	end_ifs = ''
	r_for_iffies.each do |fi|
		end_ifs = "</xsl:if>"*fi
		document = document.sub('∆',"</w:t></w:r></w:p>#{end_ifs}</xsl:for-each><w:p><w:r><w:t>")
	end



  ###########################
  # ⁂ - an XSLT block insert

  replace = document.split('⁂')

  if (((replace.size-1) % 2) != 0)
    raise ReportingError.new("Uneven number of ⁂. This is usually caused by a mismatch in a variable.")
  end

  count = 0
  replace.each do |omega|
    if (count % 2) == 0
      count = count + 1
      next
    end

    omega = compress(omega)

    # Word puts the XSLT code block into a paragraph node.
    # If we want this to be paragraph agnostic so we can use it in any context (Ex. to change the color of a single
    # table cell) we can use the ⁂! modifier
    # This will remove the <w:p> and </w:p> that are wrapping our code block
    if omega[0] == "!"
      replace[count-1] = replace[count-1][0..replace[count-1].rindex(/<w:p[ >]/)-1]
  		replace[count] = "#{CGI::unescapeHTML(omega[1..-1])}"
      replace[count+1] = replace[count+1][replace[count+1].index("</w:p>")+"</w:p>".length..-1]
    else
  		replace[count] = "#{CGI::unescapeHTML(omega)}"
    end

    count = count + 1
  end

  document = replace.join("")



	###############################
	# ツ - Placeholder for image

	replace = document.split('ツ')

	if (((replace.size-1) % 2) != 0)
        raise ReportingError.new("Uneven number of ツ. This is usually caused by a mismatch in a variable.")
	end

	count = 0
	replace.each do |omega|
		if (count % 2) == 0
			count = count + 1
			next
		end

		# Execute when between two ツ
		omega = compress(omega)

		replace[count]="[!!#{omega.downcase}!!]"

		count = count + 1
	end

	# remove all the ツ and put the document back together
	document = replace.join("")



  ###########################

  # UNUSED
  #	≠
  ###############################

	# final changes placed here
	document = white_space(document)
  # add in xslt footer
  document = document + @bottom

  #this if for xpathes/xslt errors. Trying to transform with empty xml will give errors if xpathes or xslt syntax is wrong
  begin

    # The following code block fixes the problem of images and shaped embedded in for loops
    # Without this, the object id would be duplicated and Word would complain that the document is corrupted
    tmpDocument = Nokogiri::XML(document)
    namespaces = tmpDocument.collect_namespaces
    forEachNodes = tmpDocument.xpath("//xsl:for-each[.//w:drawing//wp:docPr[@id]|.//w:drawing//wps:cNvPr[@id]]", namespaces)

    if forEachNodes
      nbDrawings = tmpDocument.xpath("count(//w:drawing//wp:docPr|//w:drawing//wps:cNvPr)", namespaces)

      forEachNodes.each_with_index do |forEach, forEachIndex|
        forEachDrawings = forEach.xpath(".//w:drawing//wp:docPr|.//w:drawing//wps:cNvPr", namespaces)
        forEachDrawings.each_with_index do |drawing, drawingIndex|
          drawing.remove_attribute("id")

          # We try as much as we can to avoid duplicated identifiers.
          # We have a 10000 id jump at every loop + 100 id jump at every drawing item + we start at the last id that was autogenerated by Word.
          drawing.prepend_child("<xsl:attribute name=\"id\"><xsl:value-of select=\"" + ((10000 * (forEachIndex+1)) + (1000 * drawingIndex) + nbDrawings.to_int).to_s + "+position()\"/></xsl:attribute>")
        end
      end

      document = tmpDocument.to_s
    end

    transformed_document = Nokogiri::XSLT(document).transform(Nokogiri::XML(''))
  rescue Exception => e
    error = e.message
    raise ReportingError.new("This exception was rescued while verificating the main XSLT well-formedness: <br/><br/>#{CGI.escapeHTML(error)}")
  end

	#return the xslt
	return document
end

# subtle annoying word 2007 v word 2010 bug. Found the solution on
# http://answers.microsoft.com/en-us/office/forum/office_2010-word/word-2010-randomly-deleting-spaces-between-words/34682f6f-7be2-4835-9c18-907b0abd5615?page=6
# Basically we replace space with alt-255 space; go figure
def white_space(document)
	document = document.gsub("<w:t xml:space=\"preserve\"> </w:t>","<w:t xml:space=\"preserve\"> </w:t>").gsub(0xE2.chr(Encoding::UTF_8), "\'").gsub("&#39;", "\'")
	return document
end

def generate_xslt_components(docx)
	# Initialize the xsl
	@top = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<xsl:stylesheet
	  version="1.0"
	  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	  <xsl:output method="xml" indent="yes"/>
	  <xsl:template match="/">
	  <xsl:variable name="low" select="\'abcdefghijklmnopqrstuvwxyz\'" /><xsl:variable name="up" select="\'ABCDEFGHIJKLMNOPQRSTUVWXYZ\'" />
		<xsl:processing-instruction name="mso-application">
		  <xsl:text>progid="Word.Document"</xsl:text>
		</xsl:processing-instruction>'
	@bottom = '</xsl:template></xsl:stylesheet>'
	document = ""
	debug = false

	list_components_xslt = {}

	#add line breaks for easier reading, only use with debugging
	#document = document.gsub('>',">\n")

	components = find_headers_footers(docx)

	components.each_with_index do |component, componentIndex|
		document = read_rels(docx,component)
    document.force_encoding('UTF-8')

		# replace {} for the sake of XSL
		document = document.gsub("{","{{").gsub("}","}}")

		# add in xslt header
		document = @top + document

		# Ω - used as a normal substituion variable
		# let's pull out variables
		replace = document.split('Ω')

		if (((replace.size-1) % 2) != 0)
			raise ReportingError.new("Uneven number of Ω. This is usually caused by a mismatch in a variable.")
		end

		count = 0
		replace.each do |omega|
			if (count % 2) == 0
				count = count + 1
				next
			end

			# Execute when between two Ω
			omega = compress(omega)

			# now, we replace omega with the real deal
			#<xsl:for-each select="report/reports">
			#<xsl:value-of select="contact_name"/>
			#</xsl:for-each>
			replace[count] = "<xsl:for-each select=\"report/reports\"><xsl:value-of select=\"#{omega.downcase}\"/></xsl:for-each>"
			count = count + 1
		end

		# remove all the Ω and put the document back together
		document = replace.join("")

		###########################

		# § - used as a user defined variable substituion variable

		# let's pull out variables
		replace = document.split('§')

		if (((replace.size-1) % 2) != 0)
			raise ReportingError.new("Uneven number of §. This is usually caused by a mismatch in a variable.")
		end

		count = 0
		replace.each do |omega|
			if (count % 2) == 0
				count = count + 1
				next
			end

			# Execute when between two §
			omega = compress(omega)

			# now, we replace omega with the real deal
			#<xsl:for-each select="report/udv">
			#<xsl:value-of select="contact_name"/>
			#</xsl:for-each>
			replace[count] = "<xsl:for-each select=\"report/udv\"><xsl:value-of select=\"#{omega.downcase}\"/></xsl:for-each>"
			count = count + 1
		end

		# remove all the § and put the document back together
		document = replace.join("")

		# final changes placed here
		document = white_space(document)

		# add in xslt footer
		document = document + @bottom
    #Trying to catch most xml/xslt/xpathes errors
    #this if for xml/xslt errors. Trying to transform with empty xml will give errors if xpathes or xslt syntax is wrong
    begin

      # The following code block fixes the problem of images and shaped embedded in for loops
      # Without this, the object id would be duplicated and Word would complain that the document is corrupted
      tmpDocument = Nokogiri::XML(document)
      namespaces = tmpDocument.collect_namespaces
      forEachDrawings = tmpDocument.xpath(".//w:drawing//wp:docPr[@id]|.//w:drawing//wps:cNvPr[@id]", namespaces)

      if forEachDrawings
        nbDrawings = tmpDocument.xpath("count(//w:drawing//wp:docPr|//w:drawing//wps:cNvPr)", namespaces)

        forEachDrawings.each_with_index do |drawing, drawingIndex|
          drawing.remove_attribute("id")

          # We try as much as we can to avoid duplicated identifiers.
          # We have a 100000 jump at every attachment + a 10000 id jump at every loop + 100 id jump at
          #    every drawing item  + we start at the last id that was autogenerated by Word.
          drawing.prepend_child("<xsl:attribute name=\"id\"><xsl:value-of select=\"" + ((100000 * (componentIndex+1)) + (1000 * drawingIndex) + nbDrawings.to_int).to_s + "+position()\"/></xsl:attribute>")
        end

        document = tmpDocument.to_s
      end

      transformed_document = Nokogiri::XSLT(document).transform(Nokogiri::XML(''))
    rescue Exception => e
      error = e.message
      raise ReportingError.new("This exception was rescued while verificating one the XSLT header or footer XSLT well-formedness: <br/><br/>#{CGI.escapeHTML(error)}")
    end
		list_components_xslt[component] = document
	end

	return list_components_xslt
end

def compress(omega)
	replacement = ""
	# if the delimeter is over multiple lines we need to put it together
	if omega =~ /\<\/w\:t\>/
		splitter = omega.gsub(">",">\n")
		splitter = splitter.gsub("<","\n<")
		splitter.split("\n").each do |multiline|
			if !(multiline =~ /\>/)
				next if multiline == ""
				#we only want the text, forget anything else
				replacement << multiline
			end
		end
	else
		return omega
	end

	return replacement
end
