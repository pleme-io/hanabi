use("hanabi", [:section])

def declaration()
  [
    section(:environment, {environment: "production"}),
    section(:server, {static_dir: ".", http_port: 8000, health_port: 8080}),
    section(:features, {enable_bff: false})
  ]
end
