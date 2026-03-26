class Clawfortify < Formula
  desc "AI Skill Security Scanner for the OpenClaw ecosystem"
  homepage "https://github.com/clawfortify/clawfortify"
  version "0.1.0"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/clawfortify/clawfortify/releases/download/v#{version}/clawfortify-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/clawfortify/clawfortify/releases/download/v#{version}/clawfortify-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_X86_SHA256"
    end
  end

  on_linux do
    url "https://github.com/clawfortify/clawfortify/releases/download/v#{version}/clawfortify-x86_64-unknown-linux-gnu.tar.gz"
    sha256 "PLACEHOLDER_LINUX_SHA256"
  end

  def install
    bin.install "clawfortify"
  end

  test do
    assert_match "clawfortify", shell_output("#{bin}/clawfortify --version")
  end
end
