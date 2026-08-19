class Bandrop < Formula
  desc "Secure, zero-config P2P file & folder transfer over your LAN"
  homepage "https://github.com/IlieBanda/bandrop"
  url "https://github.com/IlieBanda/bandrop/archive/refs/heads/main.tar.gz"
  version "0.4.0"
  license "MIT"
  head "https://github.com/IlieBanda/bandrop.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "openssl@3"
  depends_on "zlib"

  def install
    system "cmake", "-S", ".", "-B", "build", *std_cmake_args
    system "cmake", "--build", "build"
    bin.install "build/bandrop"
  end

  test do
    assert_match "bandrop #{version}", shell_output("#{bin}/bandrop --version")
  end
end
