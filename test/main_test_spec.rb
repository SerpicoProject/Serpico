
require File.expand_path '../../helpers/test_helper.rb', __FILE__


class SerpicoTests < MiniTest::Test

  include Rack::Test::Methods

  # leaving this in here for prep of authd tests
  # include FactoryGirl::Syntax::Methods
  
  # FactoryGirl.define do
  #   factory :user, class: User do
  #     username "test"
  #     password "serpicorulez"
  #     admin true
  #   end
  # end

  def app
    Server.new
  end

  def test_before_auth
    get '/idontexist'
    assert_equal 404,last_response.status

    get '/no_access'
    assert_equal 200,last_response.status

    get '/admin/dbbackup'
    assert_equal 302,last_response.status

    get '/info'
    assert_equal 302,last_response.status

    get '/logout'
    assert_equal 302,last_response.status

    get '/admin/'
    assert_equal 302,last_response.status

    get '/admin/admin_plugins'
    assert_equal 302,last_response.status

    get '/admin/plugins'
    assert_equal 302,last_response.status

    get '/report/:id/report_plugins'
    assert_equal 302,last_response.status

    get '/admin/add_user'
    assert_equal 302,last_response.status

    get '/admin/pull'
    assert_equal 302,last_response.status

    get '/admin/list_user'
    assert_equal 302,last_response.status

    get '/admin/edit_user/:id'
    assert_equal 302,last_response.status

    get '/admin/delete/:id'
    assert_equal 302,last_response.status

    get '/admin/add_user/:id'
    assert_equal 302,last_response.status

    get '/admin/del_user_report/:id/:author'
    assert_equal 302,last_response.status

    get '/master/findings'
    assert_equal 302,last_response.status

    get '/master/findings/f/:type'
    assert_equal 302,last_response.status

    get '/master/findings/new'
    assert_equal 302,last_response.status

    get '/master/findings/:id/edit'
    assert_equal 302,last_response.status

    get '/mapping/:id/nessus/:mappingid/delete'
    assert_equal 302,last_response.status

    get '/mapping/:id/burp/:mappingid/delete'
    assert_equal 302,last_response.status

    get '/mapping/:id/vulnmap/:mappingid/delete'
    assert_equal 302,last_response.status

    get '/master/findings/:id/delete'
    assert_equal 302,last_response.status

    get '/master/findings/:id/preview'
    assert_equal 302,last_response.status

    get '/master/export'
    assert_equal 302,last_response.status

    get '/master/import'
    assert_equal 302,last_response.status

    get '/admin/templates'
    assert_equal 302,last_response.status

    get '/admin/templates/add'
    assert_equal 302,last_response.status

    get '/admin/templates/:id/download'
    assert_equal 302,last_response.status

    get '/admin/delete/templates/:id'
    assert_equal 302,last_response.status

    get '/admin/templates/:id/edit'
    assert_equal 302,last_response.status

    get '/report/list'
    assert_equal 302,last_response.status

    get '/report/new'
    assert_equal 302,last_response.status

    get '/report/:id/attachments'
    assert_equal 302,last_response.status

    get '/report/:id/import_nessus'
    assert_equal 302,last_response.status

    get '/report/:id/import_burp'
    assert_equal 302,last_response.status

    get '/report/:id/upload_attachments'
    assert_equal 302,last_response.status

    get '/report/:id/attachments/:att_id'
    assert_equal 302,last_response.status

    get '/report/:id/attachments/delete/:att_id'
    assert_equal 302,last_response.status

    get '/report/:id/remove'
    assert_equal 302,last_response.status

    get '/report/:id/edit'
    assert_equal 302,last_response.status

    get '/report/:id/additional_features'
    assert_equal 302,last_response.status

    get '/report/:id/user_defined_variables'
    assert_equal 302,last_response.status

    get '/report/:id/findings'
    assert_equal 302,last_response.status

    get '/report/:id/status'
    assert_equal 302,last_response.status

    get '/report/:id/findings_add'
    assert_equal 302,last_response.status

    get '/report/:id/findings/new'
    assert_equal 302,last_response.status

    get '/report/:id/findings/:finding_id/edit'
    assert_equal 302,last_response.status

    get '/report/:id/findings/:finding_id/upload'
    assert_equal 302,last_response.status

    get '/report/:id/findings/:finding_id/remove'
    assert_equal 302,last_response.status

    get '/report/:id/findings/:finding_id/preview'
    assert_equal 302,last_response.status

    get '/report/:id/generate'
    assert_equal 302,last_response.status

    get '/report/:id/export'
    assert_equal 302,last_response.status

    get '/report/import'
    assert_equal 302,last_response.status

    get '/report/:id/text_status'
    assert_equal 302,last_response.status

    get '/report/:id/asciidoc_status'
    assert_equal 302,last_response.status

    get '/report/:id/presentation'
    assert_equal 302,last_response.status

    post '/admin/add_user'
    assert_equal 302,last_response.status

    post '/info'
    assert_equal 302,last_response.status

    post '/login'
    assert_equal 302,last_response.status

    post '/admin/add_user'
    assert_equal 302,last_response.status

    post '/admin/add_user/:id'
    assert_equal 302,last_response.status

    post '/master/findings/new'
    assert_equal 302,last_response.status

    post '/master/findings/:id/edit'
    assert_equal 302,last_response.status

    post '/master/import'
    assert_equal 302,last_response.status

    post '/admin/templates/add'
    assert_equal 302,last_response.status

    post '/admin/templates/edit'
    assert_equal 302,last_response.status

    post '/report/new'
    assert_equal 302,last_response.status

    post '/report/:id/import_autoadd'
    assert_equal 302,last_response.status

    post '/report/:id/upload_attachments'
    assert_equal 302,last_response.status

    post '/report/:id/edit'
    assert_equal 302,last_response.status

    post '/report/:id/user_defined_variables'
    assert_equal 302,last_response.status

    post '/report/:id/findings_add'
    assert_equal 302,last_response.status

    post '/report/:id/findings/new'
    assert_equal 302,last_response.status

    post '/report/:id/findings/:finding_id/edit'
    assert_equal 302,last_response.status

    post '/report/import'
    assert_equal 302,last_response.status

  end

end
