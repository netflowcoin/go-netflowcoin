Pod::Spec.new do |spec|
  spec.name         = 'sdvn'
  spec.version      = '{{.Version}}'
  spec.license      = { :type => 'GNU Lesser General Public License, Version 3.0' }
  spec.homepage     = 'https://github.com/seaskycheng/sdvn'
  spec.authors      = { {{range .Contributors}}
		'{{.Name}}' => '{{.Email}}',{{end}}
	}
  spec.summary      = 'iOS sdvn Client'
  spec.source       = { :git => 'https://github.com/seaskycheng/sdvn.git', :commit => '{{.Commit}}' }

	spec.platform = :ios
  spec.ios.deployment_target  = '9.0'
	spec.ios.vendored_frameworks = 'Frameworks/sdvn.framework'

	spec.prepare_command = <<-CMD
    curl https://sdvnstore.blob.core.windows.net/builds/{{.Archive}}.tar.gz | tar -xvz
    mkdir Frameworks
    mv {{.Archive}}/sdvn.framework Frameworks
    rm -rf {{.Archive}}
  CMD
end
