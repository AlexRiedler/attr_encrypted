# frozen_string_literal: true

if defined?(ActiveRecord::Base)
  module AttrEncrypted
    module Adapters
      module ActiveRecord
        def self.extended(base) # :nodoc:
          base.class_eval do

            # https://github.com/attr-encrypted/attr_encrypted/issues/68
            alias_method :reload_without_attr_encrypted, :reload
            def reload(*args, &block)
              result = reload_without_attr_encrypted(*args, &block)
              self.class.encrypted_attributes.keys.each do |attribute_name|
                instance_variable_set("@#{attribute_name}", nil)
              end
              result
            end

            attr_encrypted_options[:encode] = true

            class << self
              alias_method :method_missing_without_attr_encrypted, :method_missing
              alias_method :method_missing, :method_missing_with_attr_encrypted
            end

            def perform_attribute_assignment(method, new_attributes, *args)
              return if new_attributes.blank?

              send method, new_attributes.reject { |k, _|  self.class.encrypted_attributes.key?(k.to_sym) }, *args
              send method, new_attributes.reject { |k, _| !self.class.encrypted_attributes.key?(k.to_sym) }, *args
            end
            private :perform_attribute_assignment

            alias_method :assign_attributes_without_attr_encrypted, :assign_attributes
            def assign_attributes(*args)
              perform_attribute_assignment :assign_attributes_without_attr_encrypted, *args
            end

            alias_method :attributes_without_attr_encrypted=, :attributes=
            def attributes=(*args)
              perform_attribute_assignment :attributes_without_attr_encrypted=, *args
            end

            alias_method :attributes_without_attr_encrypted, :attributes
            def attributes
              # make sure to load all the encrypted attributes
              self.class.encrypted_attributes.each do |attr, v|
                send(attr)
              end
              # reject encrypted attributes from result of this function
              # so they do not get serialized on accident
              encryped_keys = self.class.encrypted_attributes.keys
              attributes_without_attr_encrypted.reject do |k, _|
                encryped_keys.include?(k.to_sym)
              end
            end
          end
        end

        protected

          # <tt>attr_encrypted</tt> method
          def attr_encrypted(*attrs)
            super
            options = attrs.extract_options!
            attr = attrs.pop
            attribute attr
            options.merge!(encrypted_attributes[attr])
            encrypted_attribute_name = (options[:attribute] ? options[:attribute] : [options[:prefix], attr, options[:suffix]].join).to_s

            define_method(attr) do
              value = super()

              # check if record is not fully loaded (e.g. partial SELECT)
              # if so, early return the value we have
              if self.class.column_names.include?(encrypted_attribute_name) &&
                  !attributes_without_attr_encrypted.include?(encrypted_attribute_name)
                return
              end

              if value.nil? && @attributes[attr.to_s].value_before_type_cast.nil?
                value = decrypt(attr, send(encrypted_attribute_name))
                @attributes[attr.to_s].instance_variable_set("@value_before_type_cast", value)
                write_attribute_without_type_cast(attr, value) if !@attributes.frozen?
              else
                instance_variable_set("@#{attr}", value)
              end
              value
            end

            define_method("#{attr}?") do
              send("#{encrypted_attribute_name}?")
            end

            define_method("#{attr}_was") do
              send(attr)
              super()
            end

            define_method("restore_#{attr}") do
              super()
              send("restore_#{encrypted_attribute_name}")
            end

            define_method("#{attr}_in_database") do
              send(attr)
              super()
            end

            define_method("#{attr}=") do |value|
              return if send(attr) == value

              send("#{encrypted_attribute_name}=", encrypt(attr, value))
              super(value)
            end
          end

          def attribute_instance_methods_as_symbols
            # We add accessor methods of the db columns to the list of instance
            # methods returned to let ActiveRecord define the accessor methods
            # for the db columns

            if connected? && table_exists?
              columns_hash.keys.inject(super) {|instance_methods, column_name| instance_methods.concat [column_name.to_sym, :"#{column_name}="]}
            else
              super
            end
          end

          def attribute_instance_methods_as_symbols_available?
            connected? && table_exists?
          end

          # Allows you to use dynamic methods like <tt>find_by_email</tt> or <tt>scoped_by_email</tt> for
          # encrypted attributes
          #
          # NOTE: This only works when the <tt>:key</tt> option is specified as a string (see the README)
          #
          # This is useful for encrypting fields like email addresses. Your user's email addresses
          # are encrypted in the database, but you can still look up a user by email for logging in
          #
          # Example
          #
          #   class User < ActiveRecord::Base
          #     attr_encrypted :email, key: 'secret key'
          #   end
          #
          #   User.find_by_email_and_password('test@example.com', 'testing')
          #   # results in a call to
          #   User.find_by_encrypted_email_and_password('the_encrypted_version_of_test@example.com', 'testing')
          def method_missing_with_attr_encrypted(method, *args, &block)
            if match = /^(find|scoped)_(all_by|by)_([_a-zA-Z]\w*)$/.match(method.to_s)
              attribute_names = match.captures.last.split('_and_')
              attribute_names.each_with_index do |attribute, index|
                if attr_encrypted?(attribute) && encrypted_attributes[attribute.to_sym][:mode] == :single_iv_and_salt
                  args[index] = send("encrypt_#{attribute}", args[index])
                  warn "DEPRECATION WARNING: This feature will be removed in the next major release."
                  attribute_names[index] = encrypted_attributes[attribute.to_sym][:attribute]
                end
              end
              method = "#{match.captures[0]}_#{match.captures[1]}_#{attribute_names.join('_and_')}".to_sym
            end
            method_missing_without_attr_encrypted(method, *args, &block)
          end
      end
    end
  end

  ActiveSupport.on_load(:active_record) do
    extend AttrEncrypted
    extend AttrEncrypted::Adapters::ActiveRecord
  end
end
