require 'sinatra'
require 'singleton'

# This class is used to reproduce an Observer-like design pattern
# => Every plugin that inherits the PluginListener class will receive the events listed in this class
#
# => Do note that the methods in this class should remain generic. If you need something that only applies to 1YWoswqCayG3vIFHuRmnku8g
#    plugin, consider doing it elsewhere.
class PluginNotifier
  include Singleton

  def initialize
    @plugins = []
  end

  # Add a plugin PluginListener
  # => The listener will be notified when a report is generated so he can add XML content into the report
  # => He will also be notified when a report is deleted so he can cleanup his local database
  def attach_plugin(observed_plugin)
    if observed_plugin and observed_plugin.class <= PluginListener
      @plugins.push observed_plugin
    else
      raise 'All observed classes must be non-null and inherit from the PluginListener class.'
    end
  end

  def detach_plugin(observed_plugin)
    @plugins.remove observed_plugin
  end

  def notify_report_generated(report_object)
    returned_xml = "<plugins>\n"

    @plugins.each { |observer|
      returned_xml << observer.notify_report_generated(report_object)
    }

    returned_xml << "</plugins>\n"
    return returned_xml
  end

  def notify_report_deleted(report_object)
    @plugins.each { |observer| observer.notify_report_deleted(report_object) }
  end
end
