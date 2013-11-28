class BinData::Base

  def current_class
    self.class
  end

  def find_parent(clazz)
    x = self
    while x.current_class != clazz
      x = x.parent
      raise "No parent with class [#{clazz}] found for [#{self.current_class}]" unless x
    end
    x
  end

end

class BinData::Choice

  def current_class
    current_choice.class
  end

end