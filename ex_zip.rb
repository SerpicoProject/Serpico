require 'zip'
require 'nokogiri'

def read_rels(zipfile,fil_r)
	content_types = ""

	Zip::File.open(zipfile) do |zipfile|
	  content_types = zipfile.read(fil_r)
	end

	return content_types
end

rels_file =  read_rels("another.docx", "word/_rels/document.xml.rels")
noko_rels =  Nokogiri::XML(rels_file)
noko_rels.root.first_element_child.after("<Relationship> ciao </Relationship>")

Zip::File.open("another.docx") do |zipfile|
  zipfile.get_output_stream("word/_rels/document.xml.rels") { |f| f.write(noko_rels) }
  end

