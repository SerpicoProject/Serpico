require 'rubygems'
require 'test/unit'
require 'rack/test'
require './serpico'

class SerpicoTests < Test::Unit::TestCase

  def test_before_check
    browser = Rack::Test::Session.new(Rack::MockSession.new(Sinatra::Application))

    browser.get '/'
    assert_equal browser.last_response.status,302

    browser.get '/login'
    assert_equal browser.last_response.status,302

    browser.get '/info'
    assert_equal browser.last_response.status,302

    browser.get '/logout'
    assert_equal browser.last_response.status,302

    browser.get '/admin/'
    assert_equal browser.last_response.status,302

    browser.get '/admin/add_user'
    assert_equal browser.last_response.status,302

    browser.get '/admin/pull'
    assert_equal browser.last_response.status,302

    browser.get '/admin/list_user'
    assert_equal browser.last_response.status,302

    browser.get '/admin/edit_user/:id'
    assert_equal browser.last_response.status,302

    browser.get '/admin/delete/:id'
    assert_equal browser.last_response.status,302

    browser.get '/admin/add_user/:id'
    assert_equal browser.last_response.status,302

    browser.get '/admin/del_user_report/:id/:author'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings/f/:type'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings/new'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings/:id/edit'
    assert_equal browser.last_response.status,302

    browser.get '/mapping/:id/nessus/:mappingid/delete'
    assert_equal browser.last_response.status,302

    browser.get '/mapping/:id/burp/:mappingid/delete'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings/:id/delete'
    assert_equal browser.last_response.status,302

    browser.get '/master/findings/:id/preview'
    assert_equal browser.last_response.status,302

    browser.get '/master/export'
    assert_equal browser.last_response.status,302

    browser.get '/master/import'
    assert_equal browser.last_response.status,302

    browser.get '/admin/templates'
    assert_equal browser.last_response.status,302

    browser.get '/admin/templates/add'
    assert_equal browser.last_response.status,302

    browser.get '/admin/templates/:id/download'
    assert_equal browser.last_response.status,302

    browser.get '/admin/delete/templates/:id'
    assert_equal browser.last_response.status,302

    browser.get '/admin/templates/:id/edit'
    assert_equal browser.last_response.status,302

    browser.get '/reports/list'
    assert_equal browser.last_response.status,200

    browser.get '/report/new'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/attachments'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/import_nessus'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/import_burp'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/upload_attachments'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/attachments/:att_id'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/attachments/delete/:att_id'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/remove'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/edit'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/additional_features'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/user_defined_variables'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/status'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings_add'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings/new'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings/:finding_id/edit'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings/:finding_id/upload'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings/:finding_id/remove'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/findings/:finding_id/preview'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/generate'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/export'
    assert_equal browser.last_response.status,302

    browser.get '/report/import'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/text_status'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/asciidoc_status'
    assert_equal browser.last_response.status,302

    browser.get '/report/:id/presentation'
    assert_equal browser.last_response.status,302

    browser.post '/admin/add_user'
    assert_equal browser.last_response.status,302

    browser.post '/info'
    assert_equal browser.last_response.status,302

    browser.post '/login'
    assert_equal browser.last_response.status,302

    browser.post '/admin/add_user'
    assert_equal browser.last_response.status,302

    browser.post '/admin/add_user/:id'
    assert_equal browser.last_response.status,302

    browser.post '/master/findings/new'
    assert_equal browser.last_response.status,302

    browser.post '/master/findings/:id/edit'
    assert_equal browser.last_response.status,302

    browser.post '/master/import'
    assert_equal browser.last_response.status,302

    browser.post '/admin/templates/add'
    assert_equal browser.last_response.status,302

    browser.post '/admin/templates/edit'
    assert_equal browser.last_response.status,302

    browser.post '/report/new'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/import_autoadd'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/upload_attachments'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/edit'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/user_defined_variables'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/findings_add'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/findings/new'
    assert_equal browser.last_response.status,302

    browser.post '/report/:id/findings/:finding_id/edit'
    assert_equal browser.last_response.status,302

    browser.post '/report/import'
    assert_equal browser.last_response.status,302

  end

end