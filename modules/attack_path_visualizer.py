from pyvis.network import Network
import tempfile


def generate_attack_path_graph(attack_logs):

    net = Network(
        height="850px",
        width="100%",

        # BACK TO BLACK
        bgcolor="#000000",

        font_color="white",

        directed=True
    )

    # =========================
    # GRAPH SPACING
    # =========================

    net.barnes_hut(
        gravity=-4200,
        central_gravity=0.12,
        spring_length=260,
        spring_strength=0.03,
        damping=0.18
    )

    previous_api = None

    for attack in attack_logs:

        api = attack["api_target"]

        severity = attack["severity"]

        attack_type = attack["attack_type"]

        source_ip = attack["source_ip"]

        # =========================
        # SOFT RISK COLORS
        # =========================

        if severity == "Critical":

            background = "#ff6666"
            border = "#cc0000"

        elif severity == "High":

            background = "#ffb84d"
            border = "#e68a00"

        elif severity == "Medium":

            background = "#fff176"
            border = "#d4c000"

        else:

            background = "#80ff80"
            border = "#00b300"

        # =========================
        # TOOLTIP INFO
        # =========================

        title = f"""
        <b>API:</b> {api}
        <br>
        <b>Severity:</b> {severity}
        <br>
        <b>Attack:</b> {attack_type}
        <br>
        <b>Source IP:</b> {source_ip}
        """

        # =========================
        # RECTANGLE NODE
        # =========================

        net.add_node(
            api,

            label=api,

            title=title,

            shape="box",

            color={

                "background": background,

                "border": border,

                "highlight": {

                    "background": background,

                    "border": border
                }
            },

            borderWidth=2,

            font={
                "size": 18,
                "face": "arial",

                # BLACK TEXT
                "color": "black"
            },

            margin=20,

            shadow={
                "enabled": True,
                "color": "rgba(255,255,255,0.08)",
                "size": 5,
                "x": 1,
                "y": 1
            }
        )

        # =========================
        # WHITE ATTACK ARROWS
        # =========================

        if previous_api and previous_api != api:

            net.add_edge(

                previous_api,
                api,

                color={
                    "color": "rgba(255,255,255,0.35)",
                    "highlight": "rgba(255,255,255,0.5)",
                    "hover": "rgba(255,255,255,0.7)"
                },

                width=2.2,

                arrows={
                    "to": {
                        "enabled": True,
                        "scaleFactor": 1.3
                    }
                },

                smooth={
                    "enabled": True,
                    "type": "curvedCW",
                    "roundness": 0.18
                },

                shadow=False
            )

        previous_api = api

    # =========================
    # INTERACTION SETTINGS
    # =========================

    net.set_options("""
    var options = {

      "nodes": {

        "shape": "box",

        "borderWidth": 2,

        "font": {
          "size": 18,
          "face": "arial",
          "color": "black"
        }

      },

      "edges": {

        "smooth": {
          "enabled": true,
          "type": "curvedCW",
          "roundness": 0.18
        }

      },

      "physics": {

        "enabled": true,
          
        "barnesHut": {

            "gravitationalConstant": -4200,

            "centralGravity": 0.12,

            "springLength": 260,

            "springConstant": 0.03,

            "damping": 0.18
        } 

      },

      "interaction": {

        "hover": true,

        "tooltipDelay": 120,

        "navigationButtons": true

      }

    }
    """)

    # =========================
    # SAVE HTML
    # =========================

    temp_file = tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".html"
    )

    net.save_graph(temp_file.name)

    with open(
        temp_file.name,
        "r",
        encoding="utf-8"
    ) as f:

        html_content = f.read()

    return html_content