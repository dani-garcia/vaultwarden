%define __spec_install_post %{nil}
%define __os_install_post %{_dbpath}/brp-compress
%define debug_package %{nil}

Name: bitwarden_rs
Summary: foo
Version: @@VERSION@@
Release: @@RELEASE@@
License: GPLv3
Group: Applications/System
Source0: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: systemd

Requires(pre): shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
%{summary}

%prep
%setup -q

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}
cp -a * %{buildroot}
mkdir -p %{buildroot}%{_localstatedir}/lib/bitwarden_rs/

%clean
rm -rf %{buildroot}

%systemd_post bitwarden_rs.service

%preun
%systemd_preun bitwarden_rs.service

%postun
%systemd_postun_with_restart bitwarden_rs.service

%files
%defattr(-,root,root,-)
%{_bindir}/*
%{_unitdir}/bitwarden_rs.service
%attr(0755,bitwarden_rs,root) %dir %{_localstatedir}/lib/bitwarden_rs

%pre
getent group bitwarden_rs >/dev/null || groupadd -r bitwarden_rs
getent passwd bitwarden_rs >/dev/null || \
    useradd -r -g bitwarden_rs -d / -s /sbin/nologin bitwarden_rs
exit 0
