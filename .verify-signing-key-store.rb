#!/usr/bin/env ruby

# The verify keystore contains a private key that needs to stay private.  This
# script fishes it out of the closed source repository where it lives so we can
# still run the whole thing locally, but don't have to open source our secrets.
# It's loaded by .env.

require 'yaml'

path_to_manifest_file = '../verify-eidas-bridge-manifests/manifests/demo/manifest.yml'

unless File.file? path_to_manifest_file then
  puts "Couldn't find manifest file. Do you have verify-eidas-bridge-manifests checked out?"
  exit 1
end

yaml = YAML.load_file path_to_manifest_file

applications = yaml.fetch 'applications'
application = applications[0]
env = application.fetch 'env'
keystore_value = env.fetch 'VERIFY_SIGNING_KEY_STORE_VALUE'

puts keystore_value

