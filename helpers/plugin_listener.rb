# For more information on the behavior of this class, look at helpers/plugin_notifier.rb
class PluginListener
  # By design, a PluginListener will return no information when notified.
  # => This should be overridden by each plugin that need to add content into a report XML
  def notify_report_generated(report_object)
    return ""
  end

    # By design, a PluginListener will do no cleanup when notified.
    # => This should be overridden by each plugin that need to cleanup his local database when reports are deleted.
  def notify_report_deleted(report_object)
    return
  end
end
