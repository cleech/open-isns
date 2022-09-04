# meson build for open-isns

project('libisns', 'c',
  version: '0.101',
  license: 'LGPL-2.1-or-later',
  default_options: [
    'c_std=gnu99',
    'warning_level=2',
    'buildtype=release',
    'libdir=/usr/lib64',
    'prefix=/usr']
  )

# get feature options
with_security = get_option('security').enabled()
with_slp = get_option('slp').enabled()
enable_shared = get_option('shared').enabled()
enable_shared_version = get_option('shared_version').enabled()
enable_static = get_option('static').enabled()

if not enable_shared and not enable_static
  error('You must enable either shared or static libary building')
endif

# get directory name override options
man_dir = get_option('mandir')
etc_dir = get_option('sysconfdir')
systemd_unit_dir = get_option('systemddir') / 'system'
sbin_dir = get_option('sbindir')
run_dir = get_option('rundir')

subdir('tests')
subdir('doc')
subdir('etc')
subdir('include/libisns')

lib_srcs = files([
  'server.c',
  'client.c',
  'objects.c',
  'callback.c',
  'timer.c',
  'vendor.c',
  'db.c',
  'db-file.c',
  'db-policy.c',
  'relation.c',
  'scope.c',
  'message.c',
  'security.c',
  'authblock.c',
  'policy.c',
  'pki.c',
  'register.c',
  'query.c',
  'getnext.c',
  'deregister.c',
  'esi.c',
  'scn.c',
  'dd.c',
  'entity.c',
  'portal-group.c',
  'storage-node.c',
  'domain.c',
  'simple.c',
  'tags.c',
  'attrs.c',
  'export.c',
  'socket.c',
  'slp.c',
  'error.c',
  'logging.c',
  'config.c',
  'parser.c',
  'buffer.c',
  'pidfile.c',
  'sysdep-unix.c',
  'util.c',
  'bitvector.c',
  'mdebug.c'])

incl_dirs = include_directories(['.', 'include'])

security_dep = []
if with_security
  security_dep = dependency('libcrypto')
endif

add_project_arguments(
  ['-D_GNU_SOURCE'],
  language: 'c')

# we will need this below
cc = meson.get_compiler('c')

#
# build our config.h file
#

conf = configuration_data()
conf.set('WITH_SECURITY', with_security)
conf.set('WITH_SLP', with_slp)
conf.set('HAVE_SLP_H', with_slp)
conf.set('RUNDIR', run_dir)

config_h = configure_file(
  output: 'config.h',
  configuration: conf)

config_incdir = include_directories('.')

config_dep = declare_dependency(
  include_directories: config_incdir,
  sources: config_h)

#
# build our library -- we always build either the static or
# the shared library, or both
#

lib_deps = [config_dep, security_dep]
if with_slp
  lib_deps += cc.find_library('slp')
endif

if enable_static
  libisns_lib = static_library('isns',
    lib_srcs,
    include_directories: incl_dirs,
    dependencies: lib_deps,
    install: true)
endif

if enable_shared
  if enable_shared_version
    shared_link_args = '-Wl,--version-script=@0@/libisns.vers'.format(meson.current_source_dir())
  else
    shared_link_args = []
  endif
  libisns_lib = shared_library('isns',
    lib_srcs,
    include_directories: incl_dirs,
    dependencies: lib_deps,
    link_args: shared_link_args,
    version: '0',
    install: true)
endif

libisns_dep = declare_dependency(link_with: libisns_lib)

#
# build binaries
#

our_dependencies = [config_dep, security_dep, libisns_dep]
if with_slp
  our_dependencies += cc.find_library('slp')
endif

executable('isnsd',
  sources: files('isnsd.c'),
  include_directories: incl_dirs,
  dependencies: our_dependencies,
  install: true,
  install_dir: sbin_dir)

executable('isnsdd',
  sources: files(['isnsdd.c', 'local.c']),
  include_directories: incl_dirs,
  dependencies: our_dependencies,
  install: true,
  install_dir: sbin_dir)

executable('isnsadm',
  sources: files('isnsadm.c'),
  include_directories: incl_dirs,
  dependencies: our_dependencies,
  install: true,
  install_dir: sbin_dir)

# a testing program (not installed, not currently used here)
e = executable('bitvector',
  sources: files('bitvector.c'),
  include_directories: incl_dirs,
  dependencies: our_dependencies,
  c_args: ['-DTEST'])
test('test bitvector', e)

# build our test files ??? (FIXME: not working)
pyunit_test_works = false
if pyunit_test_works
  test_progs = []
  foreach t: tests
    e = executable(t,
      sources: files('tests' / t + '.c'),
      include_directories: incl_dirs,
      dependencies: our_dependencies)
    test_progs += e
  endforeach
endif

#
# man pages
#

foreach m: man8_pages
  install_man(m, install_dir: man_dir / 'man8')
endforeach
foreach m: man5_pages
  install_man(m, install_dir: man_dir / 'man5')
endforeach

#
# config files
#

foreach c: config_files
  install_data(c,
    install_dir: etc_dir / 'isns')
endforeach

#
# systemd service files
#

systemd_files = files([
  'isnsd.service',
  'isnsd.socket'])
foreach f: systemd_files
  install_data(f,
    install_dir: systemd_unit_dir)
endforeach

#
# our package file
#

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries: libisns_lib,
  version: '0',
  name: 'libisns',
  description: 'iSNS userspace library')

#
# public header files
#

# one template file, and the rest are static
if false
  configure_file(
    input: template_hdr_file,
    output: template_hdr_name,
    configuration: conf,
    install: true,
    install_dir: get_option('includedir') / 'libisns')
  install_headers(static_hdr_files,
    install_dir: get_option('includedir') / 'libisns')
endif

#
# create our runtime directory (empty)
#

install_subdir('isns',
  install_dir: '/var/lib',
  install_mode: 'r--------')
