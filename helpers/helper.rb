require 'rubygems'

# The helper class exists to do string manipulation and heavy lifting

def url_escape_hash(hash)
	hash.each do |k,v|
		v = CGI::escapeHTML(v)

    if v
			# convert bullets
			v = v.gsub("*-","<bullet>")
			v = v.gsub("-*","</bullet>")	
			
			#convert h4
			v = v.gsub("[==","<h4>")
			v = v.gsub("==]","</h4>")	
   
      		#convert indent text
			v = v.gsub("[--","<indented>")
			v = v.gsub("--]","</indented>")
			
			#convert indent text
			v = v.gsub("[~~","<italics>")
			v = v.gsub("~~]","</italics>")				      
    end

		# replace linebreaks with paragraph xml elements
		if v =~ /\r\n/
			new_v = ""
			brs = v.split("\r\n")
			brs.each do |br|
				new_v << "<paragraph>"
				new_v << br
				new_v << "</paragraph>"
			end
		
			v = new_v
		elsif k == "remediation" or k == "overview" or k == "poc"
			new_v = "<paragraph>#{v}</paragraph>"
			v = new_v
		end
		
		hash[k] = v
	end
	
	return hash
end

def meta_markup(text)
	new_text = text.gsub("<paragraph>","&#x000A;").gsub("</paragraph>","")
	new_text = new_text.gsub("<bullet>","*-").gsub("</bullet>","-*")
	new_text = new_text.gsub("<h4>","[==").gsub("</h4>","==]")
	new_text = new_text.gsub("<code>","[[[").gsub("</code>","]]]")
	new_text = new_text.gsub("<indented>","[--").gsub("</indented>","--]")
	new_text = new_text.gsub("<italics>","[~~").gsub("</italics>","~~]")
end


# URL escaping messes up the inserted XML, this method switches it back to XML elements

def meta_markup_unencode(findings_xml, customer_name)
	
  # code tags get added in later
	findings_xml = findings_xml.gsub("[[[","<code>")		
	findings_xml = findings_xml.gsub("]]]","</code>")

	# creates paragraphs			
	findings_xml = findings_xml.gsub("&lt;paragraph&gt;","<paragraph>")		
	findings_xml = findings_xml.gsub("&lt;/paragraph&gt;","</paragraph>")
	# same for the bullets
	findings_xml = findings_xml.gsub("&lt;bullet&gt;","<bullet>")		
	findings_xml = findings_xml.gsub("&lt;/bullet&gt;","</bullet>")
	# same for the h4
	findings_xml = findings_xml.gsub("&lt;h4&gt;","<h4>")		
	findings_xml = findings_xml.gsub("&lt;/h4&gt;","</h4>")
	# same for the code markings
	findings_xml = findings_xml.gsub("&lt;code&gt;","<code>")		
	findings_xml = findings_xml.gsub("&lt;/code&gt;","</code>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;indented&gt;","<indented>")		
	findings_xml = findings_xml.gsub("&lt;/indented&gt;","</indented>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;italics&gt;","<italics>")		
	findings_xml = findings_xml.gsub("&lt;/italics&gt;","</italics>")
	
  # changes the <<CUSTOMER>> marks
  if customer_name
	  findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;CUSTOMER&amp;gt;&amp;gt;","#{customer_name}")
  end

  #this is for re-upping the comment fields
  findings_xml = findings_xml.gsub("&lt;modified&gt;","<modified>")		
  findings_xml = findings_xml.gsub("&lt;/modified&gt;","</modified>")
  
  findings_xml = findings_xml.gsub("&lt;new_finding&gt;","<new_finding>")		
  findings_xml = findings_xml.gsub("&lt;/new_finding&gt;","</new_finding>")

  # these are for beautification
  findings_xml = findings_xml.gsub("&amp;quot;","\"")
  findings_xml = findings_xml.gsub("&amp;","&")
  findings_xml = findings_xml.gsub("&amp;lt;","&lt;").gsub("&amp;gt;","&gt;")

  return findings_xml
end

def compare_text(new_text, orig_text)
  if orig_text == nil
    # there is no master finding, must be new
    t = ""
    t << "<new_finding></new_finding>#{new_text}"
    return t
  end

  if new_text == orig_text
    return new_text
  else
    n_t = ""
    
    n_t << "<modified></modified>#{new_text}"
    return n_t
  end
end

