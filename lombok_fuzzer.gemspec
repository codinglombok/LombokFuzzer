Gem::Specification.new do |s|
  s.name        = 'lombokfuzzer'
  s.version     = ENV.fetch('RELEASE_VERSION', '0.0.0')
  s.summary     = 'LombokFuzzer — universal fuzzing framework'
  s.description = 'Universal fuzzing framework — dist JS content package. Part of the Lombok Ecosystem.'
  s.authors     = ['codinglombok']
  s.homepage    = 'https://github.com/codinglombok/LombokFuzzer'
  s.license     = 'Apache-2.0'
  s.files       = Dir['dist/**/*'] + ['README.md', 'LICENSE']
  s.metadata    = {
    'source_code_uri'   => 'https://github.com/codinglombok/LombokFuzzer',
    'bug_tracker_uri'   => 'https://github.com/codinglombok/LombokFuzzer/issues',
    'changelog_uri'     => 'https://github.com/codinglombok/LombokFuzzer/releases',
    'github_repo'       => 'https://github.com/codinglombok/LombokFuzzer',
  }
end
