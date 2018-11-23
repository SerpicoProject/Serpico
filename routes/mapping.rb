require 'sinatra'
require './config'

# Delete a mapping from finding
get '/mapping/:id/nessus/:mappingid/delete' do
  # Check for kosher name in report name
  id = params[:id]

  mappingid = params[:mappingid]

  @map = NessusMapping.first(templatefindings_id: id, pluginid: mappingid)

  @map.destroy
  redirect to("/master/findings/#{id}/edit")
end

# Delete a mapping from finding
get '/mapping/:id/burp/:mappingid/delete' do
  # Check for kosher name in report name
  id = params[:id]

  mappingid = params[:mappingid]

  @map = BurpMapping.first(templatefindings_id: id, pluginid: mappingid)

  @map.destroy
  redirect to("/master/findings/#{id}/edit")
end

# Delete a vuln mapping from finding
get '/mapping/:id/vulnmap/:mappingid/delete' do
  # Check for kosher name in report name
  id = params[:id]

  mappingid = params[:mappingid]

  @vulnmappings = VulnMappings.first(templatefindings_id: id, id: mappingid)
  @vulnmappings.destroy
  redirect to("/master/findings/#{id}/edit")
end
