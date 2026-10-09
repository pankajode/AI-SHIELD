import pyttsx3


def speak_alert(message):
    try:
        engine = pyttsx3.init()

        engine.setProperty("rate", 165)
        engine.setProperty("volume", 1.0)

        engine.say(message)
        engine.runAndWait()

        engine.stop()

    except Exception as error:
        print(f"Voice alert unavailable: {error}")


if __name__ == "__main__":
    speak_alert(
        "AI Shield warning. "
        "This is a voice alert system test."
    )