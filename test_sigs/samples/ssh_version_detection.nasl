# Sample SSH Version Detection
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999002");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Service detection");
  script_require_ports("Services/ssh", 22);
  script_tag(name:"summary", value:"Detects the SSH server version.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
banner = get_ssh_server_banner(port:port);

if(banner) {
  if("OpenSSH" >< banner) {
    set_kb_item(name:"ssh/openssh", value:TRUE);
    version = eregmatch(pattern:"OpenSSH_([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"ssh/openssh/version", value:version[1]);
    }
  }
}
