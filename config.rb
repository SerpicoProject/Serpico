require 'json'

class Config
    private_class_method :new # Don't allow instantiation.
    @config = nil
    def self._get_config()
        @defaults = JSON.parse(File.read('./config.json.defaults'))
        @config = JSON.parse(File.read('./config.json'))
    end

    def self._get(key)
        Config._get_config() unless @config
        return @config[key] if @config.key?(key)
        return @defaults[key] # Fallback to default values
    end

    def self.[](key) return Config._get(key) end

    def self.[]=(key, val)
        Config._get_config() unless @config
        @config[key] = val
    end

    def self.key?(key)
        Config._get_config() unless @config
        return @config.key?(key)
    end
end

