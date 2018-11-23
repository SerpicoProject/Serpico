require 'rubygems'
require 'data_mapper'
require 'digest/sha1'
require 'dm-migrations'

# Initialize the Master DB
DataMapper.setup(:default, "sqlite://#{Dir.pwd}/db/master.db")

class TemplateFindings
  include DataMapper::Resource

  property :id, Serial
  property :title, String, required: true, length: 200
  property :damage, Integer, required: false
  property :reproducability, Integer, required: false
  property :exploitability, Integer, required: false
  property :affected_users, Integer, required: false
  property :discoverability, Integer, required: false
  property :dread_total, Integer, required: false
  property :effort, String, required: false
  property :type, String, required: false, length: 200
  property :overview, String, length: 20_000, required: false
  property :poc, String, length: 20_000, required: false
  property :remediation, String, length: 20_000, required: false
  property :references, String, length: 20_000, required: false
  property :approved, Boolean, required: false, default: true
  property :risk, Integer, required: false
  property :affected_hosts, String, length: 20_000, required: false

  # CVSSv2
  property :av, String, required: false
  property :ac, String, required: false
  property :au, String, required: false
  property :c, String, required: false
  property :i, String, required: false
  property :a, String, required: false
  property :e, String, required: false
  property :rl, String, required: false
  property :rc, String, required: false
  property :cdp, String, required: false
  property :td, String, required: false
  property :cr, String, required: false
  property :ir, String, required: false
  property :ar, String, required: false
  property :cvss_base, Float, required: false
  property :cvss_impact, Float, required: false
  property :cvss_exploitability, Float, required: false
  property :cvss_temporal, Float, required: false
  property :cvss_environmental, Float, required: false
  property :cvss_modified_impact, Float, required: false
  property :cvss_total, Float, required: false
  property :ease, String, required: false
  property :c2_vs, String, length: 300, required: false

  # CVSSv3
  property :attack_vector, String, required: false
  property :attack_complexity, String, required: false
  property :privileges_required, String, required: false
  property :user_interaction, String, required: false
  property :scope_cvss, String, required: false
  property :confidentiality, String, required: false
  property :integrity, String, required: false
  property :availability, String, required: false
  property :exploit_maturity, String, required: false
  property :remeditation_level, String, required: false
  property :report_confidence, String, required: false
  property :confidentiality_requirement, String, required: false
  property :integrity_requirement, String, required: false
  property :availability_requirement, String, required: false
  property :mod_attack_vector, String, required: false
  property :mod_attack_complexity, String, required: false
  property :mod_privileges_required, String, required: false
  property :mod_user_interaction, String, required: false
  property :mod_scope, String, required: false
  property :mod_confidentiality, String, required: false
  property :mod_integrity, String, required: false
  property :mod_availability, String, required: false
  property :cvss_base_score, Float, required: false
  property :cvss_impact_score, Float, required: false
  property :cvss_mod_impact_score, Float, required: false
  property :c3_vs, String, length: 300, required: false

  # Risk Matrix
  property :severity, String, required: false
  property :likelihood, String, required: false
  property :severity_rationale, String, length: 20_000, required: false
  property :likelihood_rationale, String, length: 20_000, required: false

  # NIST800
  property :nist_impact, String, :required => false
  property :nist_likelihood, String, :required => false
  property :nist800_total, Float, :required => false
  property :impact_val, Float, :required => false
  property :likelihood_val, Float, :required => false
  property :nist_rating, String, :required => false

  property :language, String, required: false
end

class Findings
  include DataMapper::Resource

  property :id, Serial
  property :finding_number, Integer, required: false
  property :report_id, Integer, required: true
  property :master_id, Integer, required: false
  property :finding_modified, Boolean, required: false
  property :title, String, required: true, length: 200
  property :damage, Integer, required: false
  property :reproducability, Integer, required: false
  property :exploitability, Integer, required: false
  property :affected_users, Integer, required: false
  property :discoverability, Integer, required: false
  property :effort, String, required: false
  property :type, String, required: false, length: 200
  property :dread_total, Integer, required: false
  property :overview, String, length: 20_000, required: false
  property :poc, String, length: 20_000, required: false
  property :remediation, String, length: 20_000, required: false
  property :notes, String, length: 1_000_000, required: false
  property :assessment_type, String, required: false
  property :references, String, length: 20_000, required: false
  property :risk, Integer, required: false
  property :affected_hosts, String, length: 1_000_000, required: false
  property :presentation_points, String, length: 100_000, required: false
  property :presentation_rem_points, String, length: 100_000, required: false

  # CVSSv2
  property :av, String, required: false
  property :ac, String, required: false
  property :au, String, required: false
  property :c, String, required: false
  property :i, String, required: false
  property :a, String, required: false
  property :e, String, required: false
  property :rl, String, required: false
  property :rc, String, required: false
  property :cdp, String, required: false
  property :td, String, required: false
  property :cr, String, required: false
  property :ir, String, required: false
  property :ar, String, required: false
  property :cvss_base, Float, required: false
  property :cvss_impact, Float, required: false
  property :cvss_exploitability, Float, required: false
  property :cvss_temporal, Float, required: false
  property :cvss_environmental, Float, required: false
  property :cvss_modified_impact, Float, required: false
  property :cvss_total, Float, required: false
  property :ease, String, required: false
  property :c2_vs, String, length: 300, required: false

  # CVSSv3
  property :attack_vector, String, required: false
  property :attack_complexity, String, required: false
  property :privileges_required, String, required: false
  property :user_interaction, String, required: false
  property :scope_cvss, String, required: false
  property :confidentiality, String, required: false
  property :integrity, String, required: false
  property :availability, String, required: false
  property :exploit_maturity, String, required: false
  property :remeditation_level, String, required: false
  property :report_confidence, String, required: false
  property :confidentiality_requirement, String, required: false
  property :integrity_requirement, String, required: false
  property :availability_requirement, String, required: false
  property :mod_attack_vector, String, required: false
  property :mod_attack_complexity, String, required: false
  property :mod_privileges_required, String, required: false
  property :mod_user_interaction, String, required: false
  property :mod_scope, String, required: false
  property :mod_confidentiality, String, required: false
  property :mod_integrity, String, required: false
  property :mod_availability, String, required: false
  property :cvss_base_score, Float, required: false
  property :cvss_impact_score, Float, required: false
  property :cvss_mod_impact_score, Float, required: false
  property :c3_vs, String, length: 300, required: false

  # Risk Matrix
  property :severity, String, required: false
  property :likelihood, String, required: false
  property :severity_rationale, String, length: 20_000, required: false
  property :likelihood_rationale, String, length: 20_000, required: false

  # NIST800
  property :nist_impact, String, :required => false
  property :nist_likelihood, String, :required => false
  property :nist800_total, Float, :required => false
  property :impact_val, Float, :required => false
  property :likelihood_val, Float, :required => false
  property :nist_rating, String, :required => false

  property :language, String, required: false
  property :state, Integer, required: false
end

class TemplateReports
  include DataMapper::Resource

  property :id, Serial
  property :consultant_name, String, required: false, length: 200
  property :consultant_company, String, required: false, length: 200
  property :consultant_phone, String
  property :consultant_email, String, required: false, length: 200
  property :contact_name, String, required: false, length: 200
  property :contact_phone, String
  property :contact_email, String
  property :contact_city, String
  property :contact_address, String
  property :contact_zip, String
  property :full_company_name, String, required: true, length: 200
  property :short_company_name, String, required: true, length: 200
  property :company_website, String
end

class User
  include DataMapper::Resource

  property :id, Serial
  property :username, String, key: true, length: (3..40), required: true
  property :hashed_password, String
  property :salt, String
  property :type, String
  property :plugin, Boolean, required: false, default: false
  property :auth_type, String, required: false
  property :created_at, DateTime, default: DateTime.now
  property :consultant_name, String, required: false
  property :consultant_company, String, required: false
  property :consultant_phone, String, required: false
  property :consultant_email, String, required: false
  property :consultant_title, String, required: false

  attr_accessor :password
  validates_presence_of :username

  def password=(pass)
    @password = pass
    self.salt = rand(36**12).to_s(36) unless salt
    self.hashed_password = User.encrypt(@password, salt)
  end

  def self.encrypt(pass, salt)
    Digest::SHA1.hexdigest(pass + salt)
  end

  def self.authenticate(username, pass)
    user = User.first(username: username)
    if user
      return user.username if User.encrypt(pass, user.salt) == user.hashed_password
    end
  end
end

class Sessions
  include DataMapper::Resource

  property :id, Serial
  property :session_key, String, length: 128
  property :username, String, length: (3..40), required: true

  def self.is_valid?(session_key)
    sessions = Sessions.first(session_key: session_key)
    return true if sessions
  end

  def self.type(session_key)
    sess = Sessions.first(session_key: session_key)

    return User.first(username: sess.username).type if sess
  end

  def self.get_username(session_key)
    sess = Sessions.first(session_key: session_key)

    return sess.username if sess
  end

  def self.is_plugin?(session_key)
    sess = Sessions.first(session_key: session_key)

    return User.first(username: sess.username).plugin if sess
  end
end

# For a metasploit connector eventually
class RemoteEndpoints
  include DataMapper::Resource

  property :id, Serial
  property :ip, String
  property :port, String
  property :type, String
  property :report_id, Integer
  property :workspace, String
  property :user, String
  property :pass, String
end

class VulnMappings
  include DataMapper::Resource

  property :id, Serial
  property :templatefindings_id, String, required: true
  property :msf_ref, String, required: true
  # property :type, String, :required => true
end

class NessusMapping
  include DataMapper::Resource

  property :id, Serial
  property :templatefindings_id, String, required: true
  property :pluginid, String, required: true
end

class BurpMapping
  include DataMapper::Resource

  property :id, Serial
  property :templatefindings_id, String, required: true
  property :pluginid, String, required: true
end

class Reports
  include DataMapper::Resource

  property :id, Serial
  property :date, String, length: 20
  property :report_type, String, length: 200
  property :report_name, String, length: 200
  property :assessment_type, String, length: 200
  property :consultant_name, String, length: 200
  property :consultant_company, String, length: 200
  property :consultant_phone, String
  property :consultant_title, String, length: 200
  property :consultant_email, String, length: 200
  property :contact_name, String, length: 200
  property :contact_phone, String
  property :contact_title, String, length: 200
  property :contact_email, String, length: 200
  property :contact_city, String
  property :contact_address, String, length: 200
  property :contact_state, String
  property :contact_zip, String
  property :full_company_name, String, length: 200
  property :short_company_name, String, length: 200
  property :company_website, String, length: 200
  property :assessment_start_date, String, length: 200
  property :assessment_end_date, String, length: 200
  property :owner, String, length: 200
  property :authors, CommaSeparatedList, required: false, lazy: false
  property :user_defined_variables, String, length: 10_000
  property :scoring, String, length: 100

  property :language, String, required: false
end

class Attachments
  include DataMapper::Resource

  property :id, Serial
  property :filename, String, length: 400
  property :filename_location, String, length: 400
  property :report_id, String, length: 30
  property :description, String, length: 500
  property :appendice, Boolean
end

class Charts
  include DataMapper::Resource

  property :id, Serial
  property :location, String, length: 400
  property :report_id, String, length: 30
  property :type, String, length: 500
end

class Hosts
  include DataMapper::Resource

  property :id, Serial
  property :ip, String
  property :port, String
end

class UserDefinedObjectTemplates
  include DataMapper::Resource

  property :id, Serial
  property :type, String, length: 300
  property :udo_properties, String, length: 10_000
end

class UserDefinedObjects
  include DataMapper::Resource

  property :id, Serial
  property :report_id, Integer, required: true
  property :template_id, Integer, required: true
  property :type, String, length: 300
  property :udo_properties, String, length: 10_000
end

class Xslt
  include DataMapper::Resource

  property :id, Serial
  property :docx_location, String, length: 400
  property :description, String, length: 400
  property :xslt_location, String, length: 400
  property :report_type, String, length: 400
  property :finding_template, Boolean, required: false, default: false
  property :status_template, Boolean, required: false, default: false
  property :screenshot_names, String, length: 10_000
  has n, :components, 'Xslt_component',
      parent_key: [:id],
      child_key: [:xslt_id]
end

class Xslt_component
  include DataMapper::Resource

  property :id, Serial
  property :xslt_location, String, length: 400
  property :name, String, length: 400

  belongs_to :xslt, 'Xslt',
             parent_key: [:id],
             child_key: [:xslt_id],
             required: true
end

DataMapper.finalize

# any differences between the data store and the data model should be fixed by this
#   As discussed in http://datamapper.org/why.html it is limited. Hopefully we never create conflicts.
DataMapper.auto_upgrade!
