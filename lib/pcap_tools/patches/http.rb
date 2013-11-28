module Net

  class HTTPRequest
    attr_accessor :time
  end

  class HTTPResponse
    attr_accessor :time

    def body=(body)
      @body = body
      @read = true
    end

  end

end