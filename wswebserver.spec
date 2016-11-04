%define name wswebserver
%define version 0.1.0
%define unmangled_version 0.1.0
%define unmangled_version 0.1.0
%define release 1

Summary: WsWebServer.
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: UNKNOWN
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: noarch
Vendor: UNKNOWN <UNKNOWN>

%description
A websocket proxy and web app server.

# -- unzip --
%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}

# -- compiling --
%build
python setup.py build

# -- install section: install to buildroot which represents the root filesystem --
%install
python setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

# init script
mkdir -p %{buildroot}/etc/rc.d/init.d/
install -m 755 fronwebsockifyd %{buildroot}/etc/rc.d/init.d/

# config files
mkdir -p %{buildroot}/etc/websockify/
install -m 644 etc/websockify/websockify %{buildroot}/etc/websockify/
install -m 644 etc/websockify/tokens %{buildroot}/etc/websockify/
install -m 644 etc/websockify/passwds %{buildroot}/etc/websockify/

# -- files to be installed in buildroot --
%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)

# init script
%{_sysconfdir}/rc.d/init.d/fronwebsockifyd
# config files
%config /etc/websockify/websockify
%config /etc/websockify/tokens
%config /etc/websockify/passwds
