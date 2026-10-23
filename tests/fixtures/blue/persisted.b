use("hanabi", [:persisted])

def operations()
  persisted(
    {
      "49433ef41bfdad3ddc6ce4e41a1042218cc23faee2529d5c12a62274af9cc23a" => "query { users { id } }",
      "0000000000000000000000000000000000000000000000000000000000000000" => "query { me { name } }",
      "short" => "query { me { id } }"
    }
  )
end
