# Sample HTTP Version Detection
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999001");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Detects the HTTP server version.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner) {
  if("Apache" >< banner) {
    set_kb_item(name:"www/apache", value:TRUE);
    version = eregmatch(pattern:"Apache/([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"www/apache/version", value:version[1]);
    }
  }
  
  if("nginx" >< banner) {
    set_kb_item(name:"www/nginx", value:TRUE);
    version = eregmatch(pattern:"nginx/([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"www/nginx/version", value:version[1]);
    }
  }
}
