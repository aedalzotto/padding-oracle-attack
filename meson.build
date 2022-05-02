project('Padding Oracle Attack', 'cpp')

incdir = include_directories('src/include')

src = [
	'src/main.cpp', 
	'src/PaddingOracle.cpp',
]

cpr = meson.get_compiler('cpp').find_library('cpr')
cryptopp = dependency('libcryptopp')

deps = [
	cpr,
	cryptopp,
]

executable('poa', src, dependencies: deps, include_directories: incdir)
