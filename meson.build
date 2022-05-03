project(
	'Padding Oracle Attack', 
	'cpp', 
	default_options : ['c_std=c11', 'cpp_std=c++20']
)

incdir = include_directories('src/include')

src = [
	'src/main.cpp', 
	'src/PaddingOracle.cpp',
]

cpr = meson.get_compiler('cpp').find_library('cpr')
cryptopp = dependency('libcryptopp')
boost = dependency('boost', modules: ['program_options'])

deps = [
	cpr,
	cryptopp,
	boost
]

executable('poa', src, dependencies: deps, include_directories: incdir)
