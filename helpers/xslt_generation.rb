# encoding: ASCII-8BIT
require 'rubygems'
require 'zipruby'
require './model/master.rb'
require 'cgi'

# This does the heavy lifting for taking a report template and creating the resulting XSLT template.
#   It needs a lot of love but it works for now.

# This is a custom error class to be thrown if the template fails to parse correctly.
class ReportingError < RuntimeError
  attr :errorString

  def initialize(errorString)
    @errorString = errorString
  end
end

def generate_xslt(docx)

# hardcoded stuff
@top = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<xsl:stylesheet
  version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="xml" indent="yes"/>
  <xsl:template match="/">
    <xsl:processing-instruction name="mso-application">
      <xsl:text>progid="Word.Document"</xsl:text>
    </xsl:processing-instruction>'

	document = ""
	debug = false

	# Read in the DOCX and grab the document.xml
	Zip::Archive.open(docx, Zip::CREATE) do |zipfile|
		# read in document.xml and store as var
		zipfile.fopen("word/document.xml") do |f|
			document = f.read # read entry content
		end
	end

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
					q << "<xsl:variable name=\"low\" select=\"'abcdefghijklmnopqrstuvwxyz'\" /><xsl:variable name=\"up\" select=\"'ABCDEFGHIJKLMNOPQRSTUVWXYZ'\" />" unless q.include?("<xsl:variable name=\"up\"")
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
				q << "<xsl:variable name=\"low\" select=\"'abcdefghijklmnopqrstuvwxyz'\" /><xsl:variable name=\"up\" select=\"'ABCDEFGHIJKLMNOPQRSTUVWXYZ'\" />" unless q.include?("<xsl:variable name=\"up\"")
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
		# add uppercase/lowercase to allow users to test for string matches (e.g. type='Database')
		cs = "<xsl:variable name=\"low\" select=\"'abcdefghijklmnopqrstuvwxyz'\" /><xsl:variable name=\"up\" select=\"'ABCDEFGHIJKLMNOPQRSTUVWXYZ'\" />"
		if document.include?("<xsl:variable name=\"up\"") or replace[count-1].include?("<xsl:variable name=\"up\"")
			cs = ""
		end

		x = replace[count-1].reverse.sub("</w:p>".reverse,"</w:p>#{cs}<xsl:if test=\"#{CGI.escapeHTML(omega.downcase).gsub("&amp;","&")}\">".reverse).reverse
		replace[count-1] = x

		replace[count]=''

		count = count + 1
	end
	document = replace.join("")


###########################
# ÷ - otherwise . Used in XSLT choose loops
	document = document.gsub('÷',"</w:t></w:r></w:p></xsl:when><xsl:otherwise><w:p><w:r><w:t>")

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

# UNUSED
#	≠
#   √
#	§
###############################

	# final changes placed here
	document = white_space(document)

	#return the xslt
	return document
end

# subtle annoying word 2007 v word 2010 bug. Found the solution on
# http://answers.microsoft.com/en-us/office/forum/office_2010-word/word-2010-randomly-deleting-spaces-between-words/34682f6f-7be2-4835-9c18-907b0abd5615?page=6
# Basically we replace space with alt-255 space; go figure
def white_space(document)
	document = document.gsub("<w:t xml:space=\"preserve\"> </w:t>","<w:t xml:space=\"preserve\"> </w:t>")
	return document
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
